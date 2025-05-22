mod api;
mod auth;
mod config;
mod consts;
mod firebase;
mod notifications;
mod state;
use config::AppConfig;
use ntex::web;
mod session;
mod utils;

use api::*;
use notifications::*;
use ntex_cors::Cors;
use state::AppState;
use utils::error::*;

#[ntex::main]
async fn main() -> Result<()> {
    let conf = AppConfig::load()?;
    env_logger::init();

    let state = AppState::new(&conf).await?;

    web::HttpServer::new(move || {
        web::App::new()
            .wrap(Cors::default())
            .state(state.clone())
            .service(set_user_metadata)
            .service(get_user_metadata)
            .service(delete_metadata_bulk)
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
