mod admin;
mod api;
mod auth;
mod config;
mod consts;
mod firebase;
mod middleware;
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
use std::sync::Arc;

use axum::{
    routing::{delete, get, post},
    Router,
};
use config::AppConfig;
use state::AppState;
use tower_http::cors::CorsLayer;
use utils::error::*;

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

async fn main_impl() -> Result<()> {
    let conf = AppConfig::load()?;

    let state = Arc::new(AppState::new(&conf).await?);

    // Build the application router with all routes defined here
    let app = Router::new()
        // API routes
        .route(
            "/metadata/{user_principal}",
            post(api::handlers::set_user_metadata),
        )
        .route(
            "/admin/metadata/{user_principal}",
            post(api::handlers::admin_set_user_metadata),
        )
        .route(
            "/metadata/{user_principal}",
            get(api::handlers::get_user_metadata),
        )
        .route(
            "/metadata/bulk",
            delete(api::handlers::delete_metadata_bulk),
        )
        .route(
            "/metadata-bulk",
            post(api::handlers::get_user_metadata_bulk),
        )
        .route(
            "/canister-to-principal/bulk",
            post(api::handlers::get_canister_to_principal_bulk),
        )
        // Notification routes
        .route(
            "/notifications/{user_principal}",
            post(notifications::register_device),
        )
        .route(
            "/notifications/{user_principal}",
            delete(notifications::unregister_device),
        )
        .route(
            "/notifications/{user_principal}/send",
            post(notifications::send_notification),
        )
        // Session routes
        .route(
            "/v2/update_session_as_registered",
            post(session::update_session_as_registered_v2),
        )
        .route(
            "/update_session_as_registered/{canister_id}",
            post(session::update_session_as_registered),
        )
        // Signup routes
        .route("/email/{user_principal}", post(signup::set_user_email))
        .route("/signup/{user_principal}", post(signup::set_signup_datetime))
        // Admin routes
        .route(
            "/admin/populate-canister-index",
            post(admin::populate_canister_index),
        )
        // OpenAPI/Swagger UI routes
        .route("/explorer/{*tail}", get(services::openapi::get_swagger))
        // Health check route
        .route("/healthz", get(api::handlers::healthz))
        // Add shared state
        .with_state(state)
        // Add middleware layers (applied in reverse order)
        .layer(sentry_tower::NewSentryLayer::new_from_top())
        .layer(sentry_tower::SentryHttpLayer::with_transaction())
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(conf.bind_address)
        .await
        .map_err(|e| Error::IO(e))?;

    log::info!("Server starting on {}", conf.bind_address);

    axum::serve(listener, app).await.map_err(|e| Error::IO(e))?;

    Ok(())
}

fn main() -> Result<()>{

    // Initialize Sentry with enhanced configuration
    let _guard = sentry::init((
        "https://ca9ac4e37832428f5804817e010068dd@apm.yral.com/6",
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: Some(
                std::env::var("ENVIRONMENT")
                    .unwrap_or_else(|_| "production".to_string())
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
            traces_sample_rate: std::env::var("SENTRY_TRACES_SAMPLE_RATE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0.5),
            attach_stacktrace: true,
            auto_session_tracking: true,
            max_breadcrumbs: 100, // Store more breadcrumbs for better context
            before_send: Some(crate::middleware::create_before_send()),
            ..Default::default()
        },
    ));

    setup_sentry_subscriber();

    log::info!("Sentry initialized successfully");

    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(
        async {
            main_impl().await.map_err(|e| Error::from(e))
        }
    )
}