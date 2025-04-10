mod api;
mod auth;
mod config;
mod consts;
mod error;
mod state;
use auth::init_jwt;
use config::AppConfig;
use ntex::web;

use api::*;
use error::*;
use ntex_cors::Cors;
use state::{AppState, RedisPool};

pub async fn init_redis(conf: &AppConfig) -> RedisPool {
    let manager = bb8_redis::RedisConnectionManager::new(conf.redis_url.clone())
        .expect("failed to open connection to redis");
    RedisPool::builder().build(manager).await.unwrap()
}

#[ntex::main]
async fn main() -> Result<()> {
    let conf = AppConfig::load()?;
    env_logger::init();

    let state = AppState {
        redis: init_redis(&conf).await,
        jwt_details: init_jwt(&conf),
    };

    web::HttpServer::new(move || {
        web::App::new()
            .wrap(Cors::default())
            .state(state.clone())
            .service(set_user_metadata)
            .service(get_user_metadata)
            .service(delete_metadata_bulk)
    })
    .bind(conf.bind_address)?
    .run()
    .await?;

    Ok(())
}
