use ic_agent::agent::AgentBuilder;
use ic_agent::identity::BasicIdentity;
use ic_agent::Agent;
use yral_canisters_client::individual_user_template::Ok;

use crate::auth::init_jwt;
use crate::auth::JwtDetails;
use crate::config::AppConfig;
use crate::firebase::Firebase;
use crate::utils::error::{Error, Result};
use crate::utils::yral_auth_jwt::YralAuthJwt;

pub type RedisPool = bb8::Pool<bb8_redis::RedisConnectionManager>;

pub static IC_AGENT_URL: &'static str = "https://ic0.app";

#[derive(Clone)]
pub struct AppState {
    pub redis: RedisPool,
    pub jwt_details: JwtDetails,
    pub yral_auth_jwt: YralAuthJwt,
    pub firebase: Firebase,
    pub backend_admin_ic_agent: ic_agent::Agent,
}

impl AppState {
    pub async fn new(app_config: &AppConfig) -> Result<Self> {
        Ok(AppState {
            redis: init_redis(app_config).await?,
            jwt_details: init_jwt(app_config)?,
            yral_auth_jwt: YralAuthJwt::init(app_config.yral_auth_public_key.clone())?,
            firebase: Firebase::new()
                .await
                .map_err(|e| Error::FirebaseApiErr(e.to_string()))?,
            backend_admin_ic_agent: init_backend_admin_key(app_config).await?,
        })
    }
}

pub async fn init_backend_admin_key(config: &AppConfig) -> Result<ic_agent::Agent> {
    let admin_id = BasicIdentity::from_pem(config.backend_admin_identity.as_slice())
        .expect("Invalid `BACKEND_ADMIN_IDENTITY`");

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
