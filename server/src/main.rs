mod admin;
mod api;
mod auth;
mod config;
mod consts;
mod firebase;
mod notifications;
mod qstash;
mod sentry_helpers;
mod sentry_middleware;
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

    // Initialize Sentry with enhanced configuration
    let _guard = sentry::init((
        "https://2e7671f1aef9c19f1f599858777accf6@apm.yral.com/6",
        sentry::ClientOptions {
            release: sentry::release_name!(),
            server_name: Some(
                hostname::get()
                    .ok()
                    .and_then(|h| h.into_string().ok())
                    .unwrap_or_else(|| "unknown".to_string())
                    .into(),
            ),
            // Capture user IPs and potentially sensitive headers when using HTTP server integrations
            send_default_pii: true,
            // Sample rate for performance monitoring (1.0 = 100%)
            traces_sample_rate: 0.1,
            // Attach stack traces to messages
            attach_stacktrace: true,
            // Enable automatic session tracking
            auto_session_tracking: true,
            ..Default::default()
        },
    ));

    log::info!("Sentry initialized successfully");

    let state = AppState::new(&conf).await?;

    web::HttpServer::new(move || {
        web::App::new()
            .wrap(sentry_middleware::SentryMiddleware)
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
