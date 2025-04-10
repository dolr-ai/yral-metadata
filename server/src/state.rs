use crate::auth::init_jwt;
use crate::auth::JwtDetails;
use crate::config::AppConfig;
use crate::firebase::Firebase;

pub type RedisPool = bb8::Pool<bb8_redis::RedisConnectionManager>;

#[derive(Clone)]
pub struct AppState {
    pub redis: RedisPool,
    pub jwt_details: JwtDetails,
    pub firebase: Firebase,
}

impl AppState {
    pub async fn new(app_config: &AppConfig) -> Self {
        AppState {
            redis: init_redis(app_config).await,
            jwt_details: init_jwt(app_config),
            firebase: Firebase::new().await,
        }
    }
}

pub async fn init_redis(conf: &AppConfig) -> RedisPool {
    let manager = bb8_redis::RedisConnectionManager::new(conf.redis_url.clone())
        .expect("failed to open connection to redis");
    RedisPool::builder().build(manager).await.unwrap()
}
