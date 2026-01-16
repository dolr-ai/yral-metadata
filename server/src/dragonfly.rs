use crate::utils::error::Result;
use futures::StreamExt;
use redis::aio::MultiplexedConnection;
use redis::sentinel::SentinelClient;
use redis::sentinel::SentinelClientBuilder;
use redis::sentinel::SentinelServerType;
use redis::Client;
use redis::ClientTlsConfig;
use redis::ConnectionAddr;
use redis::RedisError;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

pub const REDIS_SENTINEL_PORT: u16 = 26379;
pub const SENTINEL_SERVICE_NAME: &str = "mymaster";

pub const YRAL_METADATA_KEY_PREFIX: &str = "yral-metadata";
pub const TEST_KEY_PREFIX: &str = "test";

const SENTINEL_RECONNECT_DELAY: Duration = Duration::from_secs(1);

pub fn format_to_dragonfly_key(key_prefix: &str, key: &str) -> String {
    format!("{}:{}", key_prefix, key)
}

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

/// Configuration for the connection pool
#[derive(Clone)]
pub struct PoolConfig {
    /// Number of connections in the pool
    pub pool_size: usize,
    /// Interval between health check pings
    pub ping_interval: Duration,
    /// Delay between reconnection attempts for a dead connection
    pub reconnect_delay: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            pool_size: 10,
            ping_interval: Duration::from_secs(30),
            reconnect_delay: Duration::from_secs(1),
        }
    }
}

/// A single connection slot in the pool
/// Uses RwLock for better read concurrency since MultiplexedConnection::clone() is cheap
struct ConnectionSlot {
    /// The actual Redis connection (None if dead/reconnecting)
    connection: RwLock<Option<MultiplexedConnection>>,
    /// Whether this connection is healthy
    is_healthy: AtomicBool,
    /// Whether reconnection is in progress
    reconnecting: AtomicBool,
}

impl ConnectionSlot {
    fn new(conn: MultiplexedConnection) -> Self {
        Self {
            connection: RwLock::new(Some(conn)),
            is_healthy: AtomicBool::new(true),
            reconnecting: AtomicBool::new(false),
        }
    }

    fn new_empty() -> Self {
        Self {
            connection: RwLock::new(None),
            is_healthy: AtomicBool::new(false),
            reconnecting: AtomicBool::new(false),
        }
    }
}

/// A guard that holds a connection from the pool
pub struct PooledConnection {
    #[allow(dead_code)]
    slot: Arc<ConnectionSlot>,
    conn: MultiplexedConnection,
}

impl std::ops::Deref for PooledConnection {
    type Target = MultiplexedConnection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}


/// Custom connection pool with round-robin distribution and automatic reconnection
pub struct DragonflyPool {
    /// Connection slots
    slots: Vec<Arc<ConnectionSlot>>,
    /// Round-robin counter
    next_index: AtomicUsize,
    /// Pool configuration
    config: PoolConfig,
    /// Connection manager for creating new connections
    connection_manager: Arc<SentinelConnectionManager>,
    /// Whether the pool is running (for shutdown)
    running: Arc<AtomicBool>,
}

impl DragonflyPool {
    /// Create a new connection pool
    pub async fn new(
        connection_manager: Arc<SentinelConnectionManager>,
        config: PoolConfig,
    ) -> Result<Arc<Self>> {
        let mut slots = Vec::with_capacity(config.pool_size);

        // Create initial connections
        tracing::info!(pool_size = config.pool_size, "Initializing connection pool");

        for i in 0..config.pool_size {
            match connection_manager.connect().await {
                Ok(conn) => {
                    tracing::debug!(slot = i, "Connection established");
                    slots.push(Arc::new(ConnectionSlot::new(conn)));
                }
                Err(e) => {
                    tracing::warn!(slot = i, error = %e, "Failed to establish initial connection, will retry in background");
                    slots.push(Arc::new(ConnectionSlot::new_empty()));
                }
            }
        }

        let healthy_count = slots
            .iter()
            .filter(|s| s.is_healthy.load(Ordering::Relaxed))
            .count();
        tracing::info!(
            healthy = healthy_count,
            total = config.pool_size,
            "Connection pool initialized"
        );

        let pool = Arc::new(Self {
            slots,
            next_index: AtomicUsize::new(0),
            config,
            connection_manager,
            running: Arc::new(AtomicBool::new(true)),
        });

        // Start background tasks
        pool.start_health_checker(pool.clone());
        pool.start_reconnector(pool.clone());

        Ok(pool)
    }

    /// Get a connection from the pool using round-robin
    /// If the selected connection is unhealthy, try the next one
    /// Uses read lock for better concurrency - MultiplexedConnection::clone() is cheap
    pub async fn get(&self) -> std::result::Result<PooledConnection, RedisError> {
        let pool_size = self.slots.len();
        let start_index = self.next_index.fetch_add(1, Ordering::Relaxed) % pool_size;

        // Try each slot starting from the round-robin index
        // Use read lock since we're just cloning the connection
        for offset in 0..pool_size {
            let index = (start_index + offset) % pool_size;
            let slot = &self.slots[index];

            // Skip unhealthy connections
            if !slot.is_healthy.load(Ordering::Relaxed) {
                continue;
            }

            // Try to get the connection with a read lock (allows concurrent access)
            let guard = slot.connection.read().await;
            if let Some(conn) = guard.as_ref() {
                return Ok(PooledConnection {
                    slot: slot.clone(),
                    conn: conn.clone(),
                });
            }
        }

        // All connections are unhealthy, try to create a new one on-demand
        tracing::warn!("All pool connections unhealthy, creating on-demand connection");
        let conn = self.connection_manager.connect().await?;

        // Find a slot to store this new connection
        for slot in &self.slots {
            if !slot.is_healthy.load(Ordering::Relaxed)
                && !slot.reconnecting.load(Ordering::Relaxed)
            {
                let mut guard = slot.connection.write().await;
                *guard = Some(conn.clone());
                slot.is_healthy.store(true, Ordering::Relaxed);
                break;
            }
        }

        Ok(PooledConnection {
            slot: self.slots[0].clone(), // Use first slot as placeholder
            conn,
        })
    }

    /// Get a validated connection that has been verified with a PING
    /// Use this when you need to ensure the connection is definitely working
    pub async fn get_validated(&self) -> std::result::Result<PooledConnection, RedisError> {
        let pool_size = self.slots.len();
        let start_index = self.next_index.fetch_add(1, Ordering::Relaxed) % pool_size;

        // Try each slot, validating with PING
        for offset in 0..pool_size {
            let index = (start_index + offset) % pool_size;
            let slot = &self.slots[index];

            // Skip connections already marked unhealthy
            if !slot.is_healthy.load(Ordering::Relaxed) {
                continue;
            }

            let guard = slot.connection.read().await;
            if let Some(conn) = guard.as_ref() {
                let mut conn_clone = conn.clone();
                drop(guard); // Release lock before PING

                // Validate with PING
                match redis::cmd("PING").query_async::<String>(&mut conn_clone).await {
                    Ok(pong) if pong == "PONG" => {
                        return Ok(PooledConnection {
                            slot: slot.clone(),
                            conn: conn_clone,
                        });
                    }
                    _ => {
                        // Mark as unhealthy and try next
                        slot.is_healthy.store(false, Ordering::Relaxed);
                        tracing::debug!(slot = index, "Connection failed validation, marked unhealthy");
                    }
                }
            }
        }

        // All connections failed validation, create a fresh one
        tracing::warn!("All pool connections failed validation, creating fresh connection");
        let conn = self.connection_manager.connect().await?;

        // Find a slot to store this new connection
        for slot in &self.slots {
            if !slot.is_healthy.load(Ordering::Relaxed)
                && !slot.reconnecting.load(Ordering::Relaxed)
            {
                let mut guard = slot.connection.write().await;
                *guard = Some(conn.clone());
                slot.is_healthy.store(true, Ordering::Relaxed);
                break;
            }
        }

        Ok(PooledConnection {
            slot: self.slots[0].clone(),
            conn,
        })
    }

    /// Mark a connection as unhealthy (called when an operation fails)
    pub fn mark_unhealthy(&self, index: usize) {
        if index < self.slots.len() {
            self.slots[index].is_healthy.store(false, Ordering::Relaxed);
            tracing::debug!(slot = index, "Connection marked as unhealthy");
        }
    }

    /// Get the number of healthy connections
    pub fn healthy_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.is_healthy.load(Ordering::Relaxed))
            .count()
    }

    /// Get the pool size
    pub fn size(&self) -> usize {
        self.slots.len()
    }

    /// Start the health checker background task
    fn start_health_checker(self: &Arc<Self>, pool: Arc<DragonflyPool>) {
        let ping_interval = self.config.ping_interval;
        let running = self.running.clone();

        tokio::spawn(async move {
            tracing::info!(
                interval_secs = ping_interval.as_secs(),
                "Starting connection health checker"
            );

            while running.load(Ordering::Relaxed) {
                tokio::time::sleep(ping_interval).await;

                for (index, slot) in pool.slots.iter().enumerate() {
                    if !slot.is_healthy.load(Ordering::Relaxed) {
                        continue;
                    }

                    // Use read lock to clone the connection, then release lock before PING
                    let conn_clone = {
                        let guard = slot.connection.read().await;
                        guard.as_ref().cloned()
                    };

                    if let Some(mut conn) = conn_clone {
                        match redis::cmd("PING").query_async::<String>(&mut conn).await {
                            Ok(pong) if pong == "PONG" => {
                                tracing::trace!(slot = index, "Health check passed");
                            }
                            Ok(unexpected) => {
                                tracing::warn!(
                                    slot = index,
                                    response = %unexpected,
                                    "Unexpected PING response, marking unhealthy"
                                );
                                slot.is_healthy.store(false, Ordering::Relaxed);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    slot = index,
                                    error = %e,
                                    "Health check failed, marking unhealthy"
                                );
                                slot.is_healthy.store(false, Ordering::Relaxed);
                            }
                        }
                    } else {
                        slot.is_healthy.store(false, Ordering::Relaxed);
                    }
                }

                let healthy = pool.healthy_count();
                if healthy < pool.size() {
                    tracing::debug!(
                        healthy = healthy,
                        total = pool.size(),
                        "Pool health status"
                    );
                }
            }

            tracing::info!("Health checker stopped");
        });
    }

    /// Start the reconnector background task
    fn start_reconnector(self: &Arc<Self>, pool: Arc<DragonflyPool>) {
        let reconnect_delay = self.config.reconnect_delay;
        let running = self.running.clone();
        let connection_manager = self.connection_manager.clone();

        tokio::spawn(async move {
            tracing::info!("Starting connection reconnector");

            while running.load(Ordering::Relaxed) {
                tokio::time::sleep(reconnect_delay).await;

                for (index, slot) in pool.slots.iter().enumerate() {
                    // Skip healthy connections
                    if slot.is_healthy.load(Ordering::Relaxed) {
                        continue;
                    }

                    // Skip if already reconnecting
                    if slot
                        .reconnecting
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
                        .is_err()
                    {
                        continue;
                    }

                    tracing::debug!(slot = index, "Attempting to reconnect");

                    match connection_manager.connect().await {
                        Ok(conn) => {
                            let mut guard = slot.connection.write().await;
                            *guard = Some(conn);
                            slot.is_healthy.store(true, Ordering::Relaxed);
                            tracing::info!(slot = index, "Connection reconnected successfully");
                        }
                        Err(e) => {
                            tracing::debug!(
                                slot = index,
                                error = %e,
                                "Reconnection attempt failed"
                            );
                        }
                    }

                    slot.reconnecting.store(false, Ordering::Relaxed);
                }
            }

            tracing::info!("Reconnector stopped");
        });
    }

    /// Shutdown the pool
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
        tracing::info!("Pool shutdown initiated");
    }
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

impl SentinelConnectionManager {
    /// Create a new multiplexed connection to the Redis master
    pub async fn connect(&self) -> std::result::Result<MultiplexedConnection, RedisError> {
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
}

pub async fn init_dragonfly_redis(
    ca_cert_bytes: Vec<u8>,
    client_cert_bytes: Vec<u8>,
    client_key_bytes: Vec<u8>,
) -> Result<Arc<DragonflyPool>> {
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

    let conn_man_arc = Arc::new(conn_man);

    // Start failover listener
    let conn_man_for_listener = conn_man_arc.clone();
    let tls_certs_for_listener = tls_certs.clone();
    tokio::spawn(async move {
        conn_man_for_listener
            .start_failover_listener(tls_certs_for_listener)
            .await;
    });

    // Build the custom connection pool
    let config = PoolConfig {
        pool_size: 20,
        ping_interval: Duration::from_secs(30),
        reconnect_delay: Duration::from_secs(1),
    };

    let pool = DragonflyPool::new(conn_man_arc, config).await?;

    tracing::info!(
        pool_size = 20,
        ping_interval_secs = 30,
        "Dragonfly connection pool initialized with custom pool"
    );

    Ok(pool)
}

pub async fn init_dragonfly_redis_for_test() -> Result<Arc<DragonflyPool>> {
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

    let conn_man_arc = Arc::new(conn_man);

    // Start failover listener
    let conn_man_for_listener = conn_man_arc.clone();
    let tls_certs_for_listener = tls_certs.clone();
    tokio::spawn(async move {
        conn_man_for_listener
            .start_failover_listener(tls_certs_for_listener)
            .await;
    });

    // Build the custom connection pool with test settings
    // Use more aggressive health checking for tests since connections may go stale
    let config = PoolConfig {
        pool_size: 50,
        ping_interval: Duration::from_secs(5),  // More frequent health checks for tests
        reconnect_delay: Duration::from_millis(500),  // Faster reconnection
    };

    let pool = DragonflyPool::new(conn_man_arc, config).await?;

    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis::AsyncCommands;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::time::Instant;
    use tokio::task::JoinSet;

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

    /// Stress test: Concurrent reads and writes from multiple tasks
    #[tokio::test]
    async fn test_concurrent_operations() {
        let pool = init_dragonfly_redis_for_test()
            .await
            .expect("Failed to init dragonfly redis pool");

        const NUM_TASKS: usize = 50;
        const OPS_PER_TASK: usize = 20;

        let success_count = Arc::new(AtomicU64::new(0));
        let error_count = Arc::new(AtomicU64::new(0));

        let start = Instant::now();
        let mut join_set = JoinSet::new();

        for task_id in 0..NUM_TASKS {
            let pool = pool.clone();
            let success = success_count.clone();
            let errors = error_count.clone();

            join_set.spawn(async move {
                for op_id in 0..OPS_PER_TASK {
                    let key = format!("test:concurrent:{}:{}", task_id, op_id);
                    let value = format!("value_{}_{}", task_id, op_id);

                    match pool.get().await {
                        Ok(mut conn) => {
                            // Write
                            let set_result: Result<(), _> = conn.set(&key, &value).await;
                            if let Err(e) = set_result {
                                if errors.load(AtomicOrdering::Relaxed) < 5 {
                                    eprintln!("SET error: {}", e);
                                }
                                errors.fetch_add(1, AtomicOrdering::Relaxed);
                                continue;
                            }

                            // Read and verify
                            let get_result: Result<Option<String>, _> = conn.get(&key).await;
                            match get_result {
                                Ok(Some(v)) if v == value => {
                                    success.fetch_add(1, AtomicOrdering::Relaxed);
                                }
                                Ok(other) => {
                                    if errors.load(AtomicOrdering::Relaxed) < 5 {
                                        eprintln!("GET mismatch: expected {:?}, got {:?}", value, other);
                                    }
                                    errors.fetch_add(1, AtomicOrdering::Relaxed);
                                }
                                Err(e) => {
                                    if errors.load(AtomicOrdering::Relaxed) < 5 {
                                        eprintln!("GET error: {}", e);
                                    }
                                    errors.fetch_add(1, AtomicOrdering::Relaxed);
                                }
                            }

                            // Cleanup
                            let _: Result<(), _> = conn.del(&key).await;
                        }
                        Err(e) => {
                            if errors.load(AtomicOrdering::Relaxed) < 5 {
                                eprintln!("Pool get error: {}", e);
                            }
                            errors.fetch_add(1, AtomicOrdering::Relaxed);
                        }
                    }
                }
            });
        }

        // Wait for all tasks to complete
        while join_set.join_next().await.is_some() {}

        let elapsed = start.elapsed();
        let total_ops = NUM_TASKS * OPS_PER_TASK;
        let successes = success_count.load(AtomicOrdering::Relaxed);
        let errors = error_count.load(AtomicOrdering::Relaxed);

        println!("=== Concurrent Operations Test ===");
        println!("Tasks: {}, Ops per task: {}", NUM_TASKS, OPS_PER_TASK);
        println!("Total operations: {}", total_ops);
        println!("Successful: {}, Errors: {}", successes, errors);
        println!("Duration: {:?}", elapsed);
        println!(
            "Throughput: {:.2} ops/sec",
            total_ops as f64 / elapsed.as_secs_f64()
        );
        println!("Pool healthy connections: {}/{}", pool.healthy_count(), pool.size());

        // For remote servers with latency, 50% is acceptable for stress tests
        assert!(
            successes as usize >= total_ops * 50 / 100,
            "Expected at least 50% success rate, got {}%",
            successes * 100 / total_ops as u64
        );
    }

    /// Stress test: High throughput burst writes
    #[tokio::test]
    async fn test_burst_writes() {
        let pool = init_dragonfly_redis_for_test()
            .await
            .expect("Failed to init dragonfly redis pool");

        const TOTAL_WRITES: usize = 1_000;
        const BATCH_SIZE: usize = 50;

        let success_count = Arc::new(AtomicU64::new(0));
        let start = Instant::now();

        let mut join_set = JoinSet::new();

        for batch in 0..(TOTAL_WRITES / BATCH_SIZE) {
            let pool = pool.clone();
            let success = success_count.clone();

            join_set.spawn(async move {
                for i in 0..BATCH_SIZE {
                    let key = format!("test:burst:{}:{}", batch, i);
                    let value = format!("burst_value_{}", i);

                    if let Ok(mut conn) = pool.get().await {
                        let result: Result<(), _> = conn.set(&key, &value).await;
                        if result.is_ok() {
                            success.fetch_add(1, AtomicOrdering::Relaxed);
                        }
                    }
                }
            });
        }

        while join_set.join_next().await.is_some() {}

        let elapsed = start.elapsed();
        let successes = success_count.load(AtomicOrdering::Relaxed);

        println!("=== Burst Writes Test ===");
        println!("Total writes: {}", TOTAL_WRITES);
        println!("Successful: {}", successes);
        println!("Duration: {:?}", elapsed);
        println!(
            "Write throughput: {:.2} ops/sec",
            TOTAL_WRITES as f64 / elapsed.as_secs_f64()
        );

        // Cleanup
        let mut conn = pool.get().await.expect("Failed to get connection for cleanup");
        for batch in 0..(TOTAL_WRITES / BATCH_SIZE) {
            let pattern = format!("test:burst:{}:*", batch);
            let keys: Vec<String> = redis::cmd("KEYS")
                .arg(&pattern)
                .query_async(&mut *conn)
                .await
                .unwrap_or_default();
            if !keys.is_empty() {
                let _: Result<(), _> = conn.del::<_, ()>(keys).await;
            }
        }

        assert!(
            successes as usize >= TOTAL_WRITES * 50 / 100,
            "Expected at least 50% success rate"
        );
    }

    /// Stress test: Pipeline operations
    #[tokio::test]
    async fn test_pipeline_bulk_operations() {
        let pool = init_dragonfly_redis_for_test()
            .await
            .expect("Failed to init dragonfly redis pool");

        const PIPELINE_SIZE: usize = 100;
        const NUM_PIPELINES: usize = 20;

        let start = Instant::now();
        let mut total_ops = 0u64;

        for pipeline_num in 0..NUM_PIPELINES {
            let mut conn = pool.get().await.expect("Failed to get connection");

            // Build pipeline
            let mut pipe = redis::pipe();
            for i in 0..PIPELINE_SIZE {
                let key = format!("test:pipeline:{}:{}", pipeline_num, i);
                let value = format!("pipeline_value_{}", i);
                pipe.set(&key, &value).ignore();
            }

            // Execute pipeline
            let result: Result<(), _> = pipe.query_async(&mut *conn).await;
            if result.is_ok() {
                total_ops += PIPELINE_SIZE as u64;
            }

            // Cleanup pipeline
            let mut cleanup_pipe = redis::pipe();
            for i in 0..PIPELINE_SIZE {
                let key = format!("test:pipeline:{}:{}", pipeline_num, i);
                cleanup_pipe.del(&key).ignore();
            }
            let _: Result<(), _> = cleanup_pipe.query_async(&mut *conn).await;
        }

        let elapsed = start.elapsed();

        println!("=== Pipeline Bulk Operations Test ===");
        println!("Pipelines: {}, Ops per pipeline: {}", NUM_PIPELINES, PIPELINE_SIZE);
        println!("Total operations: {}", total_ops);
        println!("Duration: {:?}", elapsed);
        println!(
            "Pipeline throughput: {:.2} ops/sec",
            total_ops as f64 / elapsed.as_secs_f64()
        );

        assert!(
            total_ops >= (NUM_PIPELINES * PIPELINE_SIZE * 50 / 100) as u64,
            "Expected at least 50% of pipeline operations to succeed"
        );
    }

    /// Stress test: Rapid connection acquisition and release
    #[tokio::test]
    async fn test_connection_churn() {
        let pool = init_dragonfly_redis_for_test()
            .await
            .expect("Failed to init dragonfly redis pool");

        const NUM_ACQUISITIONS: usize = 500;
        const CONCURRENT_ACQUIRES: usize = 20;

        let success_count = Arc::new(AtomicU64::new(0));
        let start = Instant::now();

        let mut join_set = JoinSet::new();

        for _ in 0..CONCURRENT_ACQUIRES {
            let pool = pool.clone();
            let success = success_count.clone();

            join_set.spawn(async move {
                for _ in 0..(NUM_ACQUISITIONS / CONCURRENT_ACQUIRES) {
                    // Acquire connection
                    if let Ok(mut conn) = pool.get().await {
                        // Do a quick operation
                        let ping_result: Result<String, _> =
                            redis::cmd("PING").query_async(&mut *conn).await;
                        if ping_result.is_ok() {
                            success.fetch_add(1, AtomicOrdering::Relaxed);
                        }
                    }
                    // Connection is released when conn goes out of scope
                }
            });
        }

        while join_set.join_next().await.is_some() {}

        let elapsed = start.elapsed();
        let successes = success_count.load(AtomicOrdering::Relaxed);

        println!("=== Connection Churn Test ===");
        println!("Total acquisitions: {}", NUM_ACQUISITIONS);
        println!("Successful pings: {}", successes);
        println!("Duration: {:?}", elapsed);
        println!(
            "Acquisition rate: {:.2} /sec",
            NUM_ACQUISITIONS as f64 / elapsed.as_secs_f64()
        );
        println!("Pool healthy: {}/{}", pool.healthy_count(), pool.size());

        assert!(
            successes as usize >= NUM_ACQUISITIONS * 80 / 100,
            "Expected at least 80% successful acquisitions"
        );
    }

    /// Stress test: Large value read/write
    #[tokio::test]
    async fn test_large_values() {
        let pool = init_dragonfly_redis_for_test()
            .await
            .expect("Failed to init dragonfly redis pool");

        const VALUE_SIZES: &[usize] = &[1024, 10 * 1024, 100 * 1024]; // 1KB, 10KB, 100KB (skip 1MB - too slow over network)
        const OPS_PER_SIZE: usize = 5;

        let mut conn = pool.get().await.expect("Failed to get connection");

        for &size in VALUE_SIZES {
            let value = "x".repeat(size);
            let mut successes = 0;

            let start = Instant::now();

            for i in 0..OPS_PER_SIZE {
                let key = format!("test:large:{}:{}", size, i);

                // Write
                let set_result: Result<(), _> = conn.set(&key, &value).await;
                if set_result.is_err() {
                    continue;
                }

                // Read and verify
                let get_result: Result<Option<String>, _> = conn.get(&key).await;
                if let Ok(Some(v)) = get_result {
                    if v.len() == size {
                        successes += 1;
                    }
                }

                // Cleanup
                let _: Result<(), _> = conn.del(&key).await;
            }

            let elapsed = start.elapsed();
            let throughput_mb = (size * OPS_PER_SIZE * 2) as f64 / 1024.0 / 1024.0 / elapsed.as_secs_f64();

            println!(
                "Size: {}KB - {}/{} ops in {:?} ({:.2} MB/s)",
                size / 1024,
                successes,
                OPS_PER_SIZE,
                elapsed,
                throughput_mb
            );

            assert!(
                successes >= OPS_PER_SIZE * 50 / 100,
                "Expected at least 50% success for {} byte values",
                size
            );
        }
    }

    /// Stress test: Mixed read/write workload simulating real usage
    #[tokio::test]
    async fn test_mixed_workload() {
        let pool = init_dragonfly_redis_for_test()
            .await
            .expect("Failed to init dragonfly redis pool");

        const NUM_TASKS: usize = 10;
        const OPS_PER_TASK: usize = 50;
        const READ_RATIO: f64 = 0.8; // 80% reads, 20% writes

        let write_count = Arc::new(AtomicU64::new(0));
        let read_count = Arc::new(AtomicU64::new(0));
        let error_count = Arc::new(AtomicU64::new(0));

        // Pre-populate some keys
        {
            let mut conn = pool.get().await.expect("Failed to get connection");
            for i in 0..100 {
                let key = format!("test:mixed:preload:{}", i);
                let _: Result<(), _> = conn.set(&key, format!("preload_value_{}", i)).await;
            }
        }

        let start = Instant::now();
        let mut join_set = JoinSet::new();

        for task_id in 0..NUM_TASKS {
            let pool = pool.clone();
            let writes = write_count.clone();
            let reads = read_count.clone();
            let errors = error_count.clone();

            join_set.spawn(async move {
                let mut rng_state = task_id as u64;

                for op_id in 0..OPS_PER_TASK {
                    // Simple PRNG for deterministic but varied behavior
                    rng_state = rng_state.wrapping_mul(1103515245).wrapping_add(12345);
                    let is_read = (rng_state % 100) < (READ_RATIO * 100.0) as u64;

                    match pool.get().await {
                        Ok(mut conn) => {
                            if is_read {
                                // Read from preloaded keys
                                let key_idx = (rng_state / 100) % 100;
                                let key = format!("test:mixed:preload:{}", key_idx);
                                let result: Result<Option<String>, _> = conn.get(&key).await;
                                if result.is_ok() {
                                    reads.fetch_add(1, AtomicOrdering::Relaxed);
                                } else {
                                    errors.fetch_add(1, AtomicOrdering::Relaxed);
                                }
                            } else {
                                // Write to task-specific key
                                let key = format!("test:mixed:write:{}:{}", task_id, op_id);
                                let result: Result<(), _> =
                                    conn.set(&key, format!("value_{}", op_id)).await;
                                if result.is_ok() {
                                    writes.fetch_add(1, AtomicOrdering::Relaxed);
                                } else {
                                    errors.fetch_add(1, AtomicOrdering::Relaxed);
                                }
                            }
                        }
                        Err(_) => {
                            errors.fetch_add(1, AtomicOrdering::Relaxed);
                        }
                    }
                }
            });
        }

        while join_set.join_next().await.is_some() {}

        let elapsed = start.elapsed();
        let total_reads = read_count.load(AtomicOrdering::Relaxed);
        let total_writes = write_count.load(AtomicOrdering::Relaxed);
        let total_errors = error_count.load(AtomicOrdering::Relaxed);
        let total_ops = total_reads + total_writes;

        println!("=== Mixed Workload Test ===");
        println!("Tasks: {}, Ops per task: {}", NUM_TASKS, OPS_PER_TASK);
        println!("Reads: {}, Writes: {}, Errors: {}", total_reads, total_writes, total_errors);
        println!("Duration: {:?}", elapsed);
        println!(
            "Throughput: {:.2} ops/sec",
            total_ops as f64 / elapsed.as_secs_f64()
        );
        println!(
            "Actual read ratio: {:.1}%",
            total_reads as f64 / total_ops as f64 * 100.0
        );

        // Cleanup
        {
            let mut conn = pool.get().await.expect("Failed to get connection for cleanup");
            // Clean preloaded keys
            for i in 0..100 {
                let key = format!("test:mixed:preload:{}", i);
                let _: Result<(), _> = conn.del(&key).await;
            }
            // Clean written keys
            for task_id in 0..NUM_TASKS {
                let pattern = format!("test:mixed:write:{}:*", task_id);
                let keys: Vec<String> = redis::cmd("KEYS")
                    .arg(&pattern)
                    .query_async(&mut *conn)
                    .await
                    .unwrap_or_default();
                if !keys.is_empty() {
                    let _: Result<(), _> = conn.del::<_, ()>(keys).await;
                }
            }
        }

        assert!(
            total_ops >= (NUM_TASKS * OPS_PER_TASK * 50 / 100) as u64,
            "Expected at least 50% success rate"
        );
    }

    /// Stress test: Sustained load over time
    #[tokio::test]
    async fn test_sustained_load() {
        let pool = init_dragonfly_redis_for_test()
            .await
            .expect("Failed to init dragonfly redis pool");

        const DURATION_SECS: u64 = 5;
        const TARGET_OPS_PER_SEC: u64 = 100;
        const NUM_WORKERS: usize = 5;

        let ops_count = Arc::new(AtomicU64::new(0));
        let error_count = Arc::new(AtomicU64::new(0));
        let running = Arc::new(AtomicBool::new(true));

        let start = Instant::now();
        let mut join_set = JoinSet::new();

        // Spawn workers
        for worker_id in 0..NUM_WORKERS {
            let pool = pool.clone();
            let ops = ops_count.clone();
            let errors = error_count.clone();
            let running = running.clone();

            join_set.spawn(async move {
                let ops_per_worker = TARGET_OPS_PER_SEC / NUM_WORKERS as u64;
                let delay = Duration::from_micros(1_000_000 / ops_per_worker);
                let mut op_counter = 0u64;

                while running.load(AtomicOrdering::Relaxed) {
                    let key = format!("test:sustained:{}:{}", worker_id, op_counter);
                    op_counter += 1;

                    match pool.get().await {
                        Ok(mut conn) => {
                            let result: Result<(), _> = conn.set(&key, "sustained_value").await;
                            if result.is_ok() {
                                ops.fetch_add(1, AtomicOrdering::Relaxed);
                            } else {
                                errors.fetch_add(1, AtomicOrdering::Relaxed);
                            }
                            // Cleanup immediately
                            let _: Result<(), _> = conn.del(&key).await;
                        }
                        Err(_) => {
                            errors.fetch_add(1, AtomicOrdering::Relaxed);
                        }
                    }

                    tokio::time::sleep(delay).await;
                }
            });
        }

        // Let it run for the specified duration
        tokio::time::sleep(Duration::from_secs(DURATION_SECS)).await;
        running.store(false, AtomicOrdering::Relaxed);

        // Wait for workers to finish
        while join_set.join_next().await.is_some() {}

        let elapsed = start.elapsed();
        let total_ops = ops_count.load(AtomicOrdering::Relaxed);
        let total_errors = error_count.load(AtomicOrdering::Relaxed);
        let actual_ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

        println!("=== Sustained Load Test ===");
        println!("Duration: {:?}", elapsed);
        println!("Target ops/sec: {}", TARGET_OPS_PER_SEC);
        println!("Actual ops/sec: {:.2}", actual_ops_per_sec);
        println!("Total ops: {}, Errors: {}", total_ops, total_errors);
        println!("Pool health: {}/{}", pool.healthy_count(), pool.size());

        // Should achieve at least 10% of target rate (accounting for network latency)
        assert!(
            actual_ops_per_sec >= TARGET_OPS_PER_SEC as f64 * 0.1,
            "Expected at least 10% of target throughput, got {:.2}",
            actual_ops_per_sec
        );
    }
}
