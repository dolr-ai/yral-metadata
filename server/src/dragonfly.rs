use crate::utils::error::{Error, Result};
use redis::aio::ConnectionLike;
use redis::aio::MultiplexedConnection;
use redis::sentinel::SentinelClient;
use redis::sentinel::SentinelClientBuilder;
use redis::sentinel::SentinelServerType;
use redis::ClientTlsConfig;
use redis::ConnectionAddr;
use std::fs;
use std::sync::Arc;
use tokio::sync::RwLock;
pub type DragonflyPool = Arc<RedisManager>;

pub const REDIS_SENTINEL_PORT: u16 = 26379;
pub const SENTINEL_SERVICE_NAME: &str = "mymaster";

pub const YRAL_METADATA_KEY_PREFIX: &str = "yral-metadata";
pub const TEST_KEY_PREFIX: &str = "test";

pub fn format_to_dragonfly_key(key_prefix: &str, key: &str) -> String {
    format!("{}:{}", key_prefix, key)
}

pub async fn init_dragonfly_redis() -> Result<DragonflyPool> {
    let ca_bytes = get_ca_cert_pem().expect("failed to read ca-cert bytes");
    let cert_bytes = get_client_cert_pem().expect("failed to read client cert bytes");
    let key_bytes = get_client_key_pem().expect("failed to read client key bytes");

    let tls_certs = redis::TlsCertificates {
        client_tls: Some(ClientTlsConfig {
            client_cert: cert_bytes,
            client_key: key_bytes,
        }),
        root_cert: Some(ca_bytes),
    };

    let hosts_str = std::env::var("DRAGONFLY_HOST")
        .expect("DRAGONFLY_HOST environment variable not set")
        .trim()
        .to_string();

    let hosts: Vec<String> = hosts_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let conn_addr: Vec<ConnectionAddr> = hosts
        .iter()
        .map(|ip| ConnectionAddr::TcpTls {
            host: ip.clone(),
            port: REDIS_SENTINEL_PORT,
            insecure: false,
            tls_params: None, // Will be set via builder
        })
        .collect();

    let dragonfly_pass =
        std::env::var("DRAGONFLY_PASSWORD").expect("failed to read redis password");
    let mut builder =
        SentinelClientBuilder::new(conn_addr, SENTINEL_SERVICE_NAME, SentinelServerType::Master)?;

    // Sentinel TLS certificates (for mTLS to sentinel)
    builder = builder.set_client_to_sentinel_certificates(tls_certs.clone());

    // Redis (Dragonfly) configuration
    builder = builder.set_client_to_redis_username("default");
    builder = builder.set_client_to_redis_password(dragonfly_pass);
    builder = builder.set_client_to_redis_certificates(tls_certs.clone());
    builder = builder.set_client_to_redis_tls_mode(redis::TlsMode::Secure);

    let mut sentinel_client = builder.build().expect("Failed to build SentinelClient");
    let conn_man = RedisManager::new(sentinel_client, SENTINEL_SERVICE_NAME.to_string())?;
    Ok(Arc::new(conn_man))
}

// to create client for testing env
pub async fn init_dragonfly_redis_for_test() -> Result<DragonflyPool> {
    let ca_bytes = get_ca_cert_pem().expect("failed to read ca-cert bytes");
    let cert_bytes = get_client_cert_pem().expect("failed to read client cert bytes");
    let key_bytes = get_client_key_pem().expect("failed to read client key bytes");

    let tls_certs = redis::TlsCertificates {
        client_tls: Some(ClientTlsConfig {
            client_cert: cert_bytes,
            client_key: key_bytes,
        }),
        root_cert: Some(ca_bytes),
    };

    let hosts_str = std::env::var("DRAGONFLY_HOST")
        .expect("DRAGONFLY_HOST environment variable not set")
        .trim()
        .to_string();

    let hosts: Vec<String> = hosts_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let conn_addr: Vec<ConnectionAddr> = hosts
        .iter()
        .map(|ip| ConnectionAddr::TcpTls {
            host: ip.clone(),
            port: REDIS_SENTINEL_PORT,
            insecure: false,
            tls_params: None, // Will be set via builder
        })
        .collect();

    let dragonfly_pass =
        std::env::var("DRAGONFLY_PASSWORD").expect("failed to read redis password");
    let mut builder =
        SentinelClientBuilder::new(conn_addr, SENTINEL_SERVICE_NAME, SentinelServerType::Master)?;

    // Sentinel TLS certificates (for mTLS to sentinel)
    builder = builder.set_client_to_sentinel_certificates(tls_certs.clone());

    // Redis (Dragonfly) configuration
    builder = builder.set_client_to_redis_username("default");
    builder = builder.set_client_to_redis_password(dragonfly_pass);
    builder = builder.set_client_to_redis_certificates(tls_certs.clone());
    builder = builder.set_client_to_redis_tls_mode(redis::TlsMode::Secure);

    let mut sentinel_client = builder.build().expect("Failed to build SentinelClient");
    let conn_man = RedisManager::new(sentinel_client, SENTINEL_SERVICE_NAME.to_string())?;
    Ok(Arc::new(conn_man))
}

// Redis Manager with multiplexed connection
pub struct RedisManager {
    sentinel_client: Arc<RwLock<SentinelClient>>,
    master_name: String,
    connection: RwLock<Option<MultiplexedConnection>>,
}

impl RedisManager {
    pub fn new(
        sentinel_client: SentinelClient,
        master_name: String,
    ) -> Result<Self, redis::RedisError> {
        Ok(Self {
            sentinel_client: Arc::new(RwLock::new(sentinel_client)),
            master_name,
            connection: RwLock::new(None),
        })
    }

    // Get or refresh multiplexed connection
    async fn get_connection(&self) -> Result<MultiplexedConnection, redis::RedisError> {
        let mut conn_guard = self.connection.write().await;

        // Check if existing connection is still valid
        if let Some(ref mut conn) = *conn_guard {
            // Try a simple ping to verify connection
            if conn.req_packed_command(&redis::cmd("PING")).await.is_ok() {
                return Ok(conn.clone());
            }
        }

        let client = self.sentinel_client.write().await.get_client()?;
        let new_conn = client.get_multiplexed_async_connection().await?;

        *conn_guard = Some(new_conn.clone());
        Ok(new_conn)
    }

    // Get a cloned connection for use (cheap clone, shares underlying connection)
    pub async fn get(&self) -> Result<MultiplexedConnection, redis::RedisError> {
        let mut attempts = 0;
        let max_attempts = 3;

        loop {
            attempts += 1;

            match self.get_connection().await {
                Ok(conn) => return Ok(conn),
                Err(e) if attempts < max_attempts => {
                    // Clear cached connection on error
                    *self.connection.write().await = None;
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn normalize_pem(pem: String) -> Vec<u8> {
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

fn get_ca_cert_pem() -> Result<Vec<u8>> {
    Ok(normalize_pem(
        std::env::var("DRAGONFLY_CA_CERT").expect("DRAGONFLY_CA_CERT env var not set"),
    ))
}

fn get_client_cert_pem() -> Result<Vec<u8>> {
    Ok(normalize_pem(
        std::env::var("DRAGONFLY_CLIENT_CERT").expect("DRAGONFLY_CLIENT_CERT env var not set"),
    ))
}

fn get_client_key_pem() -> Result<Vec<u8>> {
    Ok(normalize_pem(
        std::env::var("DRAGONFLY_CLIENT_KEY").expect("DRAGONFLY_CLIENT_KEY env var not set"),
    ))
}
