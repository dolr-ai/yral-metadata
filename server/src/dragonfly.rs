use crate::utils::error::Result;
use bb8::{ManageConnection, Pool};
use futures::StreamExt;
use redis::aio::MultiplexedConnection;
use redis::sentinel::SentinelClient;
use redis::sentinel::SentinelClientBuilder;
use redis::sentinel::SentinelServerType;
use redis::Client;
use redis::ClientTlsConfig;
use redis::ConnectionAddr;
use redis::RedisError;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub type DragonflyPool = Pool<SentinelConnectionManager>;

pub const REDIS_SENTINEL_PORT: u16 = 26379;
pub const SENTINEL_SERVICE_NAME: &str = "mymaster";

pub const YRAL_METADATA_KEY_PREFIX: &str = "yral-metadata";
pub const TEST_KEY_PREFIX: &str = "test";

const SENTINEL_RECONNECT_DELAY: Duration = Duration::from_secs(1);

pub fn format_to_dragonfly_key(key_prefix: &str, key: &str) -> String {
    format!("{}:{}", key_prefix, key)
}

// ============================================================================
// PEM Utilities
// ============================================================================

pub fn normalize_pem(pem: String) -> Vec<u8> {
    let normalized = pem
        .replace("\\n", "\n")
        .replace("\\r\\n", "\n")
        .replace("\\r", "")
        .replace("\r\n", "\n")
        .replace("\r", "")
        .trim()
        .to_string();
    if normalized.ends_with('\n') {
        normalized.into_bytes()
    } else {
        format!("{}\n", normalized).into_bytes()
    }
}

pub fn get_ca_cert_pem() -> Result<Vec<u8>> {
    Ok(normalize_pem(
        std::env::var("DRAGONFLY_CA_CERT").expect("DRAGONFLY_CA_CERT env var not set"),
    ))
}

pub fn get_client_cert_pem() -> Result<Vec<u8>> {
    Ok(normalize_pem(
        std::env::var("DRAGONFLY_CLIENT_CERT").expect("DRAGONFLY_CLIENT_CERT env var not set"),
    ))
}

pub fn get_client_key_pem() -> Result<Vec<u8>> {
    Ok(normalize_pem(
        std::env::var("DRAGONFLY_CLIENT_KEY").expect("DRAGONFLY_CLIENT_KEY env var not set"),
    ))
}

fn build_tls_certs(
    ca_cert_bytes: Vec<u8>,
    client_cert_bytes: Vec<u8>,
    client_key_bytes: Vec<u8>,
) -> redis::TlsCertificates {
    redis::TlsCertificates {
        client_tls: Some(ClientTlsConfig {
            client_cert: client_cert_bytes,
            client_key: client_key_bytes,
        }),
        root_cert: Some(ca_cert_bytes),
    }
}

fn get_hosts_from_env() -> Vec<String> {
    let hosts_str = std::env::var("DRAGONFLY_HOSTS")
        .expect("DRAGONFLY_HOSTS environment variable not set")
        .trim()
        .to_string();

    hosts_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ============================================================================
// Sentinel Connection Manager
// ============================================================================

#[derive(Clone)]
pub struct SentinelConnectionManager {
    sentinel_client: Arc<RwLock<SentinelClient>>,
    master_name: String,
    /// Cached master client - invalidated only by pub/sub failover events
    cached_master: Arc<RwLock<Option<Client>>>,
}

impl SentinelConnectionManager {
    pub fn new(sentinel_client: SentinelClient, master_name: String) -> Result<Self> {
        Ok(Self {
            sentinel_client: Arc::new(RwLock::new(sentinel_client)),
            master_name,
            cached_master: Arc::new(RwLock::new(None)),
        })
    }

    /// Called when pub/sub detects a failover - clears the cached master
    async fn on_failover_detected(&self) {
        tracing::warn!("Failover detected! Invalidating master cache");
        let mut cache = self.cached_master.write().await;
        *cache = None;
    }

    /// Get master client - uses cache if available, otherwise queries Sentinel
    async fn get_master_client(&self) -> std::result::Result<Client, RedisError> {
        // Fast path: return cached client if available
        {
            let cache = self.cached_master.read().await;
            if let Some(ref client) = *cache {
                return Ok(client.clone());
            }
        }

        // Slow path: query Sentinel and cache the result
        let mut cache = self.cached_master.write().await;

        // Double-check after acquiring write lock
        if let Some(ref client) = *cache {
            return Ok(client.clone());
        }

        let mut sentinel = self.sentinel_client.write().await;
        let client = sentinel.get_client()?;

        // Log the discovered master for debugging
        let connection_info = client.get_connection_info();
        let (host, port) = match connection_info.addr() {
            redis::ConnectionAddr::Tcp(h, p) => (h.clone(), *p),
            redis::ConnectionAddr::TcpTls { host, port, .. } => (host.clone(), *port),
            _ => ("unknown".to_string(), 0),
        };

        tracing::info!(host = %host, port = port, "Discovered master from Sentinel");

        *cache = Some(client.clone());
        Ok(client)
    }

    pub async fn start_failover_listener(self: Arc<Self>, tls_certs: redis::TlsCertificates) {
        let hosts = get_hosts_from_env();

        if hosts.is_empty() {
            tracing::error!("No Sentinel hosts configured, failover listener disabled");
            return;
        }

        tracing::info!(
            hosts = ?hosts,
            "Starting Sentinel failover listener"
        );

        loop {
            for host in &hosts {
                tracing::debug!(host = %host, "Attempting Sentinel pub/sub connection");

                match self
                    .subscribe_to_sentinel(host.clone(), tls_certs.clone())
                    .await
                {
                    Ok(()) => {
                        tracing::warn!(
                            host = %host,
                            "Sentinel subscription ended unexpectedly"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            host = %host,
                            error = %e,
                            "Sentinel subscription failed"
                        );
                    }
                }

                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            tracing::warn!(
                "All Sentinel connections failed, retrying in {:?}",
                SENTINEL_RECONNECT_DELAY
            );
            tokio::time::sleep(SENTINEL_RECONNECT_DELAY).await;
        }
    }

    async fn subscribe_to_sentinel(
        &self,
        host: String,
        tls_certs: redis::TlsCertificates,
    ) -> std::result::Result<(), RedisError> {
        let url = format!("rediss://{}:{}", host, REDIS_SENTINEL_PORT);
        let client = redis::Client::build_with_tls(url, tls_certs)?;

        let mut pubsub = client.get_async_pubsub().await?;

        pubsub.subscribe("+switch-master").await?;
        pubsub.subscribe("+sdown").await?;
        pubsub.subscribe("+odown").await?;
        pubsub.subscribe("-sdown").await?;
        pubsub.subscribe("-odown").await?;

        tracing::info!(host = %host, "Successfully subscribed to Sentinel events");

        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let channel: String = msg.get_channel()?;
            let payload: String = msg.get_payload()?;

            tracing::debug!(
                channel = %channel,
                payload = %payload,
                "Received Sentinel event"
            );

            match channel.as_str() {
                "+switch-master" => {
                    if payload.starts_with(&self.master_name) {
                        tracing::warn!(
                            payload = %payload,
                            "Master switched! Triggering failover handling"
                        );
                        self.on_failover_detected().await;
                    }
                }
                "+odown" => {
                    if payload.contains("master") && payload.contains(&self.master_name) {
                        tracing::warn!(
                            payload = %payload,
                            "Master is objectively down, failover imminent"
                        );
                        self.on_failover_detected().await;
                    }
                }
                "+sdown" => {
                    if payload.contains("master") && payload.contains(&self.master_name) {
                        tracing::warn!(
                            payload = %payload,
                            "Master is subjectively down"
                        );
                    }
                }
                _ => {
                    // Other events (-sdown, -odown) are informational
                }
            }
        }

        Ok(())
    }
}

impl ManageConnection for SentinelConnectionManager {
    type Connection = MultiplexedConnection;
    type Error = RedisError;

    async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        // Try with cached master first
        match self.get_master_client().await {
            Ok(client) => match client.get_multiplexed_async_connection().await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    tracing::warn!(error = %e, "Connection to cached master failed, invalidating cache");
                    self.on_failover_detected().await;
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "Failed to get master client");
            }
        }

        // Retry after cache invalidation
        let client = self.get_master_client().await?;
        client.get_multiplexed_async_connection().await
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> std::result::Result<(), Self::Error> {
        let pong: String = redis::cmd("PING").query_async(conn).await?;
        match pong.as_str() {
            "PONG" => Ok(()),
            _ => {
                Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid PING response").into())
            }
        }
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

pub async fn init_dragonfly_redis(
    ca_cert_bytes: Vec<u8>,
    client_cert_bytes: Vec<u8>,
    client_key_bytes: Vec<u8>,
) -> Result<DragonflyPool> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let tls_certs = build_tls_certs(
        ca_cert_bytes.clone(),
        client_cert_bytes.clone(),
        client_key_bytes.clone(),
    );

    let hosts = get_hosts_from_env();

    let conn_addr: Vec<ConnectionAddr> = hosts
        .iter()
        .map(|ip| ConnectionAddr::TcpTls {
            host: ip.clone(),
            port: REDIS_SENTINEL_PORT,
            insecure: false,
            tls_params: None,
        })
        .collect();

    let dragonfly_pass = std::env::var("DRAGONFLY_PASSWORD")
        .expect("DRAGONFLY_PASSWORD environment variable not set");

    let mut builder =
        SentinelClientBuilder::new(conn_addr, SENTINEL_SERVICE_NAME, SentinelServerType::Master)?;

    builder = builder.set_client_to_sentinel_certificates(tls_certs.clone());

    builder = builder.set_client_to_redis_username("default");
    builder = builder.set_client_to_redis_password(dragonfly_pass);
    builder = builder.set_client_to_redis_certificates(tls_certs.clone());
    builder = builder.set_client_to_redis_tls_mode(redis::TlsMode::Secure);

    let sentinel_client = builder.build().expect("Failed to build SentinelClient");
    let conn_man =
        SentinelConnectionManager::new(sentinel_client, SENTINEL_SERVICE_NAME.to_string())?;

    let conn_man_for_listener = Arc::new(conn_man.clone());
    let tls_certs_for_listener = tls_certs.clone();
    tokio::spawn(async move {
        conn_man_for_listener
            .start_failover_listener(tls_certs_for_listener)
            .await;
    });

    // Build the pool with optimal settings
    let pool = DragonflyPool::builder()
        .max_size(20) // Maximum connections
        .min_idle(Some(5)) // Keep 5 warm connections ready
        .connection_timeout(Duration::from_secs(5)) // Don't wait too long for new connections
        .idle_timeout(Some(Duration::from_secs(300))) // Recycle idle connections after 5 min
        .max_lifetime(Some(Duration::from_secs(1800))) // Refresh all connections every 30 min
        .build(conn_man)
        .await?;

    // Warm up the cache by making a connection and executing PING
    // This ensures the master is cached before real requests come in
    {
        let mut conn = pool.get().await?;
        let _: String = redis::cmd("PING").query_async(&mut *conn).await?;
        tracing::info!("Dragonfly pool warmed up successfully");
    }

    tracing::info!(
        max_size = 20,
        min_idle = 5,
        "Dragonfly connection pool initialized"
    );

    Ok(pool)
}

pub async fn init_dragonfly_redis_for_test() -> Result<DragonflyPool> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let ca_bytes = get_ca_cert_pem().expect("Failed to read CA cert");
    let cert_bytes = get_client_cert_pem().expect("Failed to read client cert");
    let key_bytes = get_client_key_pem().expect("Failed to read client key");

    let tls_certs = build_tls_certs(ca_bytes.clone(), cert_bytes.clone(), key_bytes.clone());

    let hosts = get_hosts_from_env();

    let conn_addr: Vec<ConnectionAddr> = hosts
        .iter()
        .map(|ip| ConnectionAddr::TcpTls {
            host: ip.clone(),
            port: REDIS_SENTINEL_PORT,
            insecure: false,
            tls_params: None,
        })
        .collect();

    let dragonfly_pass = std::env::var("DRAGONFLY_PASSWORD")
        .expect("DRAGONFLY_PASSWORD environment variable not set");

    let mut builder =
        SentinelClientBuilder::new(conn_addr, SENTINEL_SERVICE_NAME, SentinelServerType::Master)?;

    builder = builder.set_client_to_sentinel_certificates(tls_certs.clone());
    builder = builder.set_client_to_redis_username("default");
    builder = builder.set_client_to_redis_password(dragonfly_pass);
    builder = builder.set_client_to_redis_certificates(tls_certs.clone());
    builder = builder.set_client_to_redis_tls_mode(redis::TlsMode::Secure);

    let sentinel_client = builder.build().expect("Failed to build SentinelClient");
    let conn_man =
        SentinelConnectionManager::new(sentinel_client, SENTINEL_SERVICE_NAME.to_string())?;

    let conn_man_for_listener = Arc::new(conn_man.clone());
    let tls_certs_for_listener = tls_certs.clone();
    tokio::spawn(async move {
        conn_man_for_listener
            .start_failover_listener(tls_certs_for_listener)
            .await;
    });

    let pool = DragonflyPool::builder()
        .max_size(50)
        .min_idle(Some(5))
        .connection_timeout(Duration::from_secs(30)) // Longer timeout for test environments
        .idle_timeout(Some(Duration::from_secs(300)))
        .max_lifetime(Some(Duration::from_secs(1800)))
        .build(conn_man)
        .await?;

    // Warm up the cache by making a connection and executing PING
    {
        let mut conn = pool.get().await?;
        let _: String = redis::cmd("PING").query_async(&mut *conn).await?;
    }

    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::AsyncCommands;

    #[tokio::test]
    async fn test_dragonfly_connection() {
        let pool = init_dragonfly_redis_for_test()
            .await
            .expect("Failed to init dragonfly redis pool");

        // Get a connection from pool
        let mut conn = pool.get().await.expect("Failed to get Redis connection");

        // Write
        let _: () = conn.set("test:hello", "hi").await.expect("SET failed");

        // Read
        let result: Option<String> = conn.get("test:hello").await.expect("GET failed");
        assert_eq!(result.as_deref(), Some("hi"), "Stored value should match");

        // Cleanup
        let _: () = conn.del("test:hello").await.expect("DEL failed");

        println!("dragonfly cluster connection test passed!");
    }
}
