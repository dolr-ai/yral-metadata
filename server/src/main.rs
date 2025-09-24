mod admin;
mod api;
mod auth;
mod config;
mod consts;
mod firebase;
mod notifications;
mod qstash;
mod services;
mod session;
mod signup;
mod state;
mod utils;

#[cfg(test)]
mod test_utils;
use api::*;
use config::AppConfig;
use notifications::*;
use ntex::web;
use ntex_cors::Cors;
use state::AppState;
use utils::error::*;

use crate::signup::{set_signup_datetime, set_user_email};

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
            .service(admin_set_user_metadata)
            .service(set_user_metadata)
            .service(set_user_email)
            .service(set_signup_datetime)
            .service(get_user_metadata)
            .service(delete_metadata_bulk)
            .service(get_user_metadata_bulk)
            .service(get_canister_to_principal_bulk)
            .service(register_device)
            .service(unregister_device)
            .service(send_notification)
            .service(session::update_session_as_registered_v2)
            .service(session::update_session_as_registered)
            .service(admin::populate_canister_index)
    })
    .bind(conf.bind_address)?
    .run()
    .await?;

    Ok(())
}
