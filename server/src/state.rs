use crate::auth::init_jwt;
use crate::auth::JwtDetails;
use crate::config::AppConfig;
use crate::error::Error;
use crate::error::Result;
use crate::firebase::Firebase;

pub type RedisPool = bb8::Pool<bb8_redis::RedisConnectionManager>;

#[derive(Clone)]
pub struct AppState {
    pub redis: RedisPool,
    pub jwt_details: JwtDetails,
    pub firebase: Firebase,
}

impl AppState {
    pub async fn new(app_config: &AppConfig) -> Result<Self> {
        Ok(AppState {
            redis: init_redis(app_config).await?,
            jwt_details: init_jwt(app_config)?,
            firebase: Firebase::new()
                .await
                .map_err(|e| Error::FirebaseApiErr(e.to_string()))?,
        })
    }
}

pub async fn init_redis(conf: &AppConfig) -> Result<RedisPool> {
    let manager = bb8_redis::RedisConnectionManager::new(conf.redis_url.clone())?;
    RedisPool::builder()
        .build(manager)
        .await
        .map_err(Error::Redis)
}
