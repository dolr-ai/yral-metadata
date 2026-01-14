use crate::auth::init_jwt;
use crate::auth::JwtDetails;
use crate::config::AppConfig;
use crate::dragonfly::{
    get_ca_cert_pem, get_client_cert_pem, get_client_key_pem, init_dragonfly_redis, DragonflyPool,
};
use crate::firebase::Firebase;
use crate::qstash::QStashState;
use crate::utils::error::{Error, Result};
use crate::utils::yral_auth_jwt::YralAuthJwt;
use ic_agent::identity::Secp256k1Identity;
use ic_agent::Agent;
pub type RedisPool = bb8::Pool<bb8_redis::RedisConnectionManager>;

pub static IC_AGENT_URL: &str = "https://ic0.app";

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
        let ca_cert_bytes = get_ca_cert_pem()?;
        let client_cert_bytes = get_client_cert_pem()?;
        let client_key_bytes = get_client_key_pem()?;
        Ok(AppState {
            redis: init_redis(app_config).await?,
            dragonfly_redis: init_dragonfly_redis(
                ca_cert_bytes,
                client_cert_bytes,
                client_key_bytes,
            )
            .await?,
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
