mod admin;
mod api;
mod auth;
mod config;
mod consts;
mod firebase;
mod notifications;
mod qstash;
mod sentry_middleware;
mod sentry_utils;
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

use crate::sentry_middleware::SentryMiddleware;
use crate::signup::{set_signup_datetime, set_user_email};

fn setup_sentry_subscriber() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,yral_metadata_server=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .with(sentry_tracing::layer())
        .init();
}

#[ntex::main]
async fn main() -> Result<()> {
    let conf = AppConfig::load()?;

    // Initialize Sentry with enhanced configuration
    let _guard = sentry::init((
        "https://ca9ac4e37832428f5804817e010068dd@apm.yral.com/6",
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: Some(
                std::env::var("ENVIRONMENT")
                    .unwrap_or_else(|_| "development".to_string())
                    .into(),
            ),
            server_name: Some(
                hostname::get()
                    .ok()
                    .and_then(|h| h.into_string().ok())
                    .unwrap_or_else(|| "unknown".to_string())
                    .into(),
            ),
            send_default_pii: true,
            traces_sample_rate: 0.5, // Increased for better observability
            attach_stacktrace: true,
            auto_session_tracking: true,
            max_breadcrumbs: 100, // Store more breadcrumbs for better context
            before_send: Some(std::sync::Arc::new(|mut event| {
                // Sanitize sensitive data before sending
                if let Some(request) = &mut event.request {
                    // Remove authorization headers from the headers map
                    request.headers.remove("authorization");
                    request.headers.remove("cookie");
                }
                Some(event)
            })),
            ..Default::default()
        },
    ));

    setup_sentry_subscriber();

    log::info!("Sentry initialized successfully");

    let state = AppState::new(&conf).await?;

    web::HttpServer::new(move || {
        web::App::new()
            .wrap(SentryMiddleware) // Add Sentry middleware first to capture all requests
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
