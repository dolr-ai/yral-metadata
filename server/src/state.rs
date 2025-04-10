use crate::auth::JwtDetails;

pub type RedisPool = bb8::Pool<bb8_redis::RedisConnectionManager>;

#[derive(Clone)]
pub struct AppState {
    pub redis: RedisPool,
    pub jwt_details: JwtDetails,
}
