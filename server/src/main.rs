mod api;
mod auth;
mod config;
mod consts;
mod firebase;
mod notifications;
mod services;
mod session;
mod state;
mod utils;
use api::*;
use config::AppConfig;
use notifications::*;
use ntex::web;
use ntex_cors::Cors;
use state::AppState;
use utils::error::*;

#[ntex::main]
async fn main() -> Result<()> {
    env_logger::init();

    let conf = AppConfig::load()?;

    let state = AppState::new(&conf).await?;

    web::HttpServer::new(move || {
        web::App::new()
            .wrap(Cors::default())
            .state(state.clone())
            .configure(services::openapi::ntex_config)
            .service(set_user_metadata)
            .service(get_user_metadata)
            .service(delete_metadata_bulk)
            .service(get_user_metadata_bulk)
            .service(register_device)
            .service(unregister_device)
            .service(send_notification)
            .service(session::update_session_as_registered)
    })
    .bind(conf.bind_address)?
    .run()
    .await?;

    Ok(())
}
