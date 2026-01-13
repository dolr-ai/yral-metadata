use std::fs;
use std::path::MAIN_SEPARATOR_STR;
use std::sync::Arc;

use crate::auth::init_jwt;
use crate::auth::JwtDetails;
use crate::config::AppConfig;
use crate::firebase::Firebase;
use crate::qstash::QStashState;
use crate::utils::error::{Error, Result};
use crate::utils::yral_auth_jwt::YralAuthJwt;
use ic_agent::identity::Secp256k1Identity;
use ic_agent::Agent;
use redis::aio::ConnectionLike;
use redis::aio::ConnectionManager;
use redis::aio::MultiplexedConnection;
use redis::sentinel::SentinelClient;
use redis::sentinel::SentinelClientBuilder;
use redis::sentinel::SentinelServerType;
use redis::AsyncCommands;
use redis::Client;
use redis::ClientTlsConfig;
use redis::ConnectionAddr;
use tokio::sync::RwLock;
pub type RedisPool = bb8::Pool<bb8_redis::RedisConnectionManager>;
pub type DragonflyPool = Arc<RedisManager>;

pub static IC_AGENT_URL: &str = "https://ic0.app";
pub const REDIS_SENTINEL_PORT: u16 = 26379;
pub const SENTINEL_SERVICE_NAME: &str = "mymaster";

#[derive(Clone)]
pub struct AppState {
    pub redis: RedisPool,
    pub dragonfly_redis: DragonflyPool,
    pub jwt_details: JwtDetails,
    pub yral_auth_jwt: YralAuthJwt,
    pub firebase: Firebase,
    pub backend_admin_ic_agent: ic_agent::Agent,
    pub qstash: QStashState,
}

impl AppState {
    pub async fn new(app_config: &AppConfig) -> Result<Self> {
        Ok(AppState {
            redis: init_redis(app_config).await?,
            dragonfly_redis: init_dragonfly_redis(app_config).await?,
            jwt_details: init_jwt(app_config)?,
            yral_auth_jwt: YralAuthJwt::init(app_config.yral_auth_public_key.clone())?,
            firebase: Firebase::new()
                .await
                .map_err(|e| Error::FirebaseApiErr(e.to_string()))?,
            backend_admin_ic_agent: init_backend_admin_key(app_config).await?,
            qstash: QStashState::init(app_config.qstash_current_signing_key.clone()),
        })
    }
}

pub async fn init_backend_admin_key(config: &AppConfig) -> Result<ic_agent::Agent> {
    let admin_id_pem: &str = config.backend_admin_identity.as_ref();
    let admin_id_pem_by = admin_id_pem.as_bytes();
    let admin_id =
        Secp256k1Identity::from_pem(admin_id_pem_by).expect("Invalid BACKEND_ADMIN_IDENTITY");

    Agent::builder()
        .with_url(IC_AGENT_URL)
        .with_identity(admin_id)
        .build()
        .map_err(|e| Error::Unknown(e.to_string()))
}

pub async fn init_redis(conf: &AppConfig) -> Result<RedisPool> {
    let manager = bb8_redis::RedisConnectionManager::new(conf.redis_url.clone())?;
    RedisPool::builder()
        .build(manager)
        .await
        .map_err(Error::Redis)
}

pub async fn init_redis_with_url(redis_url: &str) -> Result<RedisPool> {
    let manager = bb8_redis::RedisConnectionManager::new(redis_url)?;
    RedisPool::builder()
        .build(manager)
        .await
        .map_err(Error::Redis)
}

pub async fn init_dragonfly_redis(conf: &AppConfig) -> Result<DragonflyPool> {
    let ca_bytes = fs::read(&conf.ca_cert_path).expect("Failed to read CA Cert");
    let cert_bytes = fs::read(&conf.client_cert_path).expect("Failed to read Client Cert");
    let key_bytes = fs::read(&conf.client_key_path).expect("Failed to read Client Key");

    let tls_certs = redis::TlsCertificates {
        client_tls: Some(ClientTlsConfig {
            client_cert: cert_bytes,
            client_key: key_bytes,
        }),
        root_cert: Some(ca_bytes),
    };

    let conn_addr: Vec<ConnectionAddr> = conf
        .dragonfly_redis_cluster
        .iter()
        .map(|ip| ConnectionAddr::TcpTls {
            host: ip.clone(),
            port: REDIS_SENTINEL_PORT,
            insecure: false,
            tls_params: None, // Will be set via builder
        })
        .collect();

    let redis_pass = std::env::var("REDIS_PASSWORD").expect("failed to read redis password");
    let mut builder =
        SentinelClientBuilder::new(conn_addr, SENTINEL_SERVICE_NAME, SentinelServerType::Master)?;

    // Sentinel TLS certificates (for mTLS to sentinel)
    builder = builder.set_client_to_sentinel_certificates(tls_certs.clone());

    // Redis (Dragonfly) configuration
    builder = builder.set_client_to_redis_username("default");
    builder = builder.set_client_to_redis_password(redis_pass);
    builder = builder.set_client_to_redis_certificates(tls_certs.clone());
    builder = builder.set_client_to_redis_tls_mode(redis::TlsMode::Secure);

    let mut sentinel_client = builder.build().expect("Failed to build SentinelClient");
    let conn_man = RedisManager::new(sentinel_client, SENTINEL_SERVICE_NAME.to_string())?;
    Ok(Arc::new(conn_man))
}

// to create client for testing env
pub async fn init_dragonfly_redis_for_test() -> Result<DragonflyPool> {
    let ca_cert_path = std::env::var("CA_CERT_PATH").expect("Failed to load ca-cert path");
    let client_cert_path =
        std::env::var("CLIENT_CERT_PATH").expect("Failed to load client cert path");
    let client_key_path = std::env::var("CLIENT_KEY_PATH").expect("Failed to load client key path");

    let sentinel_nodes: Vec<String> = std::env::var("DRAGONFLY_REDIS_CLUSTER")
        .expect("DRAGONFLY_REDIS_CLUSTER not set")
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let ca_bytes = fs::read(ca_cert_path).expect("Failed to read CA Cert");
    let cert_bytes = fs::read(client_cert_path).expect("Failed to read Client Cert");
    let key_bytes = fs::read(client_key_path).expect("Failed to read Client Key");

    let tls_certs = redis::TlsCertificates {
        client_tls: Some(ClientTlsConfig {
            client_cert: cert_bytes,
            client_key: key_bytes,
        }),
        root_cert: Some(ca_bytes),
    };

    let conn_addr: Vec<ConnectionAddr> = sentinel_nodes
        .iter()
        .map(|ip| ConnectionAddr::TcpTls {
            host: ip.clone(),
            port: REDIS_SENTINEL_PORT,
            insecure: false,
            tls_params: None, // Will be set via builder
        })
        .collect();

    let redis_pass = std::env::var("REDIS_PASSWORD").expect("failed to read redis password");
    let mut builder =
        SentinelClientBuilder::new(conn_addr, SENTINEL_SERVICE_NAME, SentinelServerType::Master)?;

    // Sentinel TLS certificates (for mTLS to sentinel)
    builder = builder.set_client_to_sentinel_certificates(tls_certs.clone());

    // Redis (Dragonfly) configuration
    builder = builder.set_client_to_redis_username("default");
    builder = builder.set_client_to_redis_password(redis_pass);
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
