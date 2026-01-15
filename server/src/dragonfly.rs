use crate::utils::error::{Error, Result};
use redis::AsyncCommands;
use redis::aio::ConnectionLike;
use redis::aio::MultiplexedConnection;
use redis::sentinel::SentinelClient;
use redis::sentinel::SentinelClientBuilder;
use redis::sentinel::SentinelServerType;
use redis::ClientTlsConfig;
use redis::ConnectionAddr;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use bb8::{Pool, ManageConnection};
use redis::RedisError;
pub type DragonflyPool = Pool<SentinelConnectionManager>;


pub const REDIS_SENTINEL_PORT: u16 = 26379;
pub const SENTINEL_SERVICE_NAME: &str = "mymaster";

pub const YRAL_METADATA_KEY_PREFIX: &str = "yral-metadata";
pub const TEST_KEY_PREFIX: &str = "test";

pub fn format_to_dragonfly_key(key_prefix: &str, key: &str) -> String {
    format!("{}:{}", key_prefix, key)
}

pub async fn init_dragonfly_redis(
    ca_cert_bytes: Vec<u8>,
    client_cert_bytes: Vec<u8>,
    client_key_bytes: Vec<u8>,
) -> Result<DragonflyPool> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let tls_certs = redis::TlsCertificates {
        client_tls: Some(ClientTlsConfig {
            client_cert: client_cert_bytes,
            client_key: client_key_bytes,
        }),
        root_cert: Some(ca_cert_bytes),
    };

    let hosts_str = std::env::var("DRAGONFLY_HOSTS")
        .expect("DRAGONFLY_HOSTS environment variable not set")
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

    let sentinel_client = builder.build().expect("Failed to build SentinelClient");
    let conn_man = SentinelConnectionManager::new(sentinel_client, SENTINEL_SERVICE_NAME.to_string())?;

    let pool = DragonflyPool::builder().build(conn_man).await?;
    Ok(pool)
}

// to create client for testing env
pub async fn init_dragonfly_redis_for_test() -> Result<DragonflyPool> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

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

    let hosts_str = std::env::var("DRAGONFLY_HOSTS")
        .expect("DRAGONFLY_HOSTS environment variable not set")
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

    let sentinel_client = builder.build().expect("Failed to build SentinelClient");
    let conn_man = SentinelConnectionManager::new(sentinel_client, SENTINEL_SERVICE_NAME.to_string())?;

    let pool = DragonflyPool::builder()
    .max_size(50)
    .connection_timeout(Duration::from_secs(30))
    .build(conn_man).await?;
    Ok(pool)
}

// // Redis Manager with multiplexed connection
// pub struct RedisManager {
//     sentinel_client: Arc<RwLock<SentinelClient>>,
//     master_name: String,
//     connection: RwLock<Option<MultiplexedConnection>>,
// }

// impl RedisManager {
//     pub fn new(
//         sentinel_client: SentinelClient,
//         master_name: String,
//     ) -> Result<Self, redis::RedisError> {
//         Ok(Self {
//             sentinel_client: Arc::new(RwLock::new(sentinel_client)),
//             master_name,
//             connection: RwLock::new(None),
//         })
//     }

//     // Get or refresh multiplexed connection
//     async fn get_connection(&self) -> Result<MultiplexedConnection, redis::RedisError> {
//         let mut conn_guard = self.connection.write().await;

//         // Check if existing connection is still valid
//         if let Some(ref mut conn) = *conn_guard {
//             // Try a simple ping to verify connection
//             if conn.req_packed_command(&redis::cmd("PING")).await.is_ok() {
//                 return Ok(conn.clone());
//             }
//         }

//         let client = self.sentinel_client.write().await.get_client()?;
//         let new_conn = client.get_multiplexed_async_connection().await?;

//         *conn_guard = Some(new_conn.clone());
//         Ok(new_conn)
//     }

//     // Get a cloned connection for use (cheap clone, shares underlying connection)
//     pub async fn get(&self) -> Result<MultiplexedConnection, redis::RedisError> {
//         let mut attempts = 0;
//         let max_attempts = 20;

//         loop {
//             attempts += 1;

//             match self.get_connection().await {
//                 Ok(conn) => return Ok(conn),
//                 Err(e) if attempts < max_attempts => {
//                     // Clear cached connection on error
//                     *self.connection.write().await = None;
//                     tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
//                     continue;
//                 }
//                 Err(e) => return Err(e),
//             }
//         }
//     }

//     pub async fn get_dedicated(&self) -> Result<MultiplexedConnection, redis::RedisError> {
//         let client = self.sentinel_client.write().await.get_client()?;
//         let new_conn = client.get_multiplexed_async_connection().await?;
//         Ok(new_conn)
//     }
// }

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



#[derive(Clone)]
pub struct SentinelConnectionManager {
    sentinel_client: Arc<RwLock<SentinelClient>>, // Assuming this is your wrapper or redis::Sentinel
    master_name: String,
}

impl SentinelConnectionManager {
    pub fn new(sentinel_client: SentinelClient, master_name: String) -> Result<Self> {
        let sentinel_client = Arc::new(RwLock::new(sentinel_client)); 
        Ok(Self {
            sentinel_client,
            master_name,
        })
    }
}

impl ManageConnection for SentinelConnectionManager {
    type Connection = MultiplexedConnection;
    type Error = RedisError;

    // This is the critical part for failover:
    // Every time the pool needs a new connection, this runs.
    // It asks Sentinel for the CURRENT master, ensuring we don't stick to a dead one.
    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        // Lock your sentinel client to get the real client
        let mut sentinel = self.sentinel_client.write().await;
        
        // Use your existing logic to get the client for the current master
        // This implicitly asks Sentinel "Who is the master right now?"
        let client = sentinel.get_client()?; 
        
        // Create the async connection
        client.get_multiplexed_async_connection().await
    }

    // Validates connections before handing them to you. 
    // If a failover happened, the old master might still accept PINGs, 
    // but usually, it will close or error out eventually.
    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        let pong: String = redis::cmd("PING").query_async(conn).await?;
        match pong.as_str() {
            "PONG" => Ok(()),
            _ => Err((redis::ErrorKind::Extension, "ping request").into()),
        }
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use redis::AsyncCommands;

    use super::*;

    #[tokio::test]
    async fn test_dragonfly_connection() {
        if std::env::var("DRAGONFLY_PASSWORD").is_err() {
            println!("Skipping test: DRAGONFLY_PASSWORD not set");
            return;
        }

        let client = init_dragonfly_redis_for_test()
            .await
            .expect("Failed to init dragonfly redis client");

        // Get a connection from pool
        let mut conn = client.get().await.expect("Failed to get Redis connection");

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
