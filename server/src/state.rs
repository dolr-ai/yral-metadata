use bb8::PooledConnection;
use ic_agent::identity::Secp256k1Identity;
use ic_agent::Agent;
use redis::AsyncCommands;
use redis::FromRedisValue;
use redis::ToRedisArgs;

use crate::auth::init_jwt;
use crate::auth::JwtDetails;
use crate::config::AppConfig;
use crate::firebase::Firebase;
use crate::utils::error::{Error, Result};
use crate::utils::yral_auth_jwt::YralAuthJwt;

pub type RedisPool = bb8::Pool<bb8_redis::RedisConnectionManager>;

pub static IC_AGENT_URL: &str = "https://ic0.app";

pub struct PooledConn<'a> {
    old: PooledConnection<'a, bb8_redis::RedisConnectionManager>,
    new: PooledConnection<'a, bb8_redis::RedisConnectionManager>,
}

impl<'a> PooledConn<'a> {
    pub async fn hset<K: ToRedisArgs + Send + Sync + Clone, V: ToRedisArgs + Send + Sync>(
        &mut self,
        key: K,
        field: &str,
        value: &V,
    ) -> Result<()> {
        let old_fut = self.old.hset(key.clone(), field, value);
        let new_fut = self.new.hset(key, field, value);

        let _: (bool, bool) = futures::try_join!(old_fut, new_fut)?;

        Ok(())
    }

    pub async fn del<K: ?Sized, RV: FromRedisValue>(&mut self, k: &K) -> Result<RV>
    where
        for<'k> &'k K: ToRedisArgs + Send + Sync,
    {
        let res = self.old.del(k).await?;
        _ = self.new.del::<_, usize>(k).await;
        Ok(res)
    }

    pub async fn hget<K: ToRedisArgs + Send + Sync, RV: FromRedisValue>(
        &mut self,
        key: K,
        field: &str,
    ) -> Result<RV> {
        self.old.hget(key, field).await.map_err(|e| e.into())
    }
}

#[derive(Clone)]
pub struct RedisClients {
    old: RedisPool,
    new: RedisPool,
}

impl RedisClients {
    pub fn new(old: RedisPool, new: RedisPool) -> Self {
        RedisClients { old, new }
    }

    pub async fn get(&self) -> Result<PooledConn<'_>> {
        let old = self.old.get().await?;
        let new = self.new.get().await?;
        Ok(PooledConn { old, new })
    }
}

#[derive(Clone)]
pub struct AppState {
    pub redis: RedisClients,
    pub jwt_details: JwtDetails,
    pub yral_auth_jwt: YralAuthJwt,
    pub firebase: Firebase,
    pub backend_admin_ic_agent: ic_agent::Agent,
}

impl AppState {
    pub async fn new(app_config: &AppConfig) -> Result<Self> {
        let redis = RedisClients::new(
            init_redis(&app_config.redis_url).await?,
            init_redis(&app_config.new_redis_url).await?,
        );

        Ok(AppState {
            redis,
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

pub async fn init_redis(url: &redis::ConnectionInfo) -> Result<RedisPool> {
    let manager = bb8_redis::RedisConnectionManager::new(url.clone())?;
    RedisPool::builder()
        .build(manager)
        .await
        .map_err(Error::Redis)
}
