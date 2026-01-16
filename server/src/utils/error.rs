use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use ic_agent::export::PrincipalError;
use redis::RedisError;
use std::env::VarError;
use thiserror::Error;
use types::{error::ApiError, ApiResult};
use utoipa::ToSchema;

use crate::services::error_wrappers::{
    AgentErrorDetail, Bb8RedisErrorDetail, ConfigErrorDetail, IOErrorData, IdentityErrorDetail,
    JwtErrorDetail, PrincipalErrorDetail, RedisErrorDetail, SerdeJsonErrorDetail, VarErrorDetail,
};

#[derive(Error, Debug, ToSchema)]
pub enum Error {
    #[error(transparent)]
    #[schema(value_type = IOErrorData)]
    IO(#[from] std::io::Error),
    #[error("failed to load config {0}")]
    #[schema(value_type = ConfigErrorDetail)]
    Config(#[from] config::ConfigError),
    #[error("{0}")]
    #[schema(value_type = IdentityErrorDetail)]
    Identity(#[from] yral_identity::Error),
    #[error("{0}")]
    #[schema(value_type = RedisErrorDetail)]
    Redis(#[from] RedisError),
    #[error("connection pool error: {0}")]
    #[schema(value_type = Bb8RedisErrorDetail)]
    Bb8(#[from] bb8::RunError<RedisError>),
    #[error("failed to deserialize json {0}")]
    #[schema(value_type = SerdeJsonErrorDetail)]
    Deser(#[from] serde_json::Error),
    #[error("jwt {0}")]
    #[schema(value_type = JwtErrorDetail)]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("auth token missing")]
    AuthTokenMissing,
    #[error("auth token invalid")]
    AuthTokenInvalid,
    #[error("firebase api error {0}")]
    FirebaseApiErr(String),
    #[error("unknown error {0}")]
    Unknown(String),
    #[error("Environment variable error: {0}")]
    #[schema(value_type = VarErrorDetail)]
    EnvironmentVariable(#[from] VarError),
    #[error("Environment variable missing: {0}")]
    EnvironmentVariableMissing(String),
    #[error("failed to mark user sessin as registered")]
    UserAlreadyRegistered(String),
    #[error("failed to initialize backend admin ic agent")]
    BackendAdminIdentityInvalid(String),
    #[error("failed to parse principal {0}")]
    #[schema(value_type = PrincipalErrorDetail)]
    InvalidPrincipal(#[from] PrincipalError),
    #[error("failed to communicate with IC: {0}")]
    #[schema(value_type = AgentErrorDetail)]
    Agent(#[from] ic_agent::AgentError),
    #[error("failed to update session: {0}")]
    UpdateSession(String),
    #[error("swagger ui error {0}")]
    SwaggerUi(String),
    #[error("invalid username, must be 3-15 alphanumeric characters")]
    InvalidUsername,
    #[error("duplicate username")]
    DuplicateUsername,
    #[error("Invalid email")]
    InvalidEmail(String),
}

impl From<&Error> for ApiResult<()> {
    fn from(value: &Error) -> Self {
        let err = match value {
            Error::IO(_) | Error::Config(_) => {
                log::warn!("internal error {value}");
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    &format!("Internal error: {}", value),
                    sentry::Level::Error,
                );
                ApiError::Unknown("internal error, reported".into())
            }
            Error::Identity(_) => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    "Invalid signature",
                    sentry::Level::Warning,
                );
                ApiError::InvalidSignature
            }
            Error::Redis(e) => {
                log::warn!("redis error {e}");
                crate::sentry_utils::add_redis_breadcrumb("error", &e.to_string(), false);
                ApiError::Redis
            }
            Error::Bb8(e) => {
                log::warn!("bb8 error {e}");
                crate::sentry_utils::add_redis_breadcrumb(
                    "connection_pool_error",
                    &e.to_string(),
                    false,
                );
                ApiError::Redis
            }
            Error::Deser(e) => {
                log::warn!("deserialization error {e}");
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    &format!("Deserialization error: {}", e),
                    sentry::Level::Error,
                );
                ApiError::Deser
            }
            Error::Jwt(_) => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    "JWT validation failed",
                    sentry::Level::Warning,
                );
                ApiError::Jwt
            }
            Error::AuthTokenMissing => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    "Auth token missing",
                    sentry::Level::Warning,
                );
                ApiError::AuthTokenMissing
            }
            Error::AuthTokenInvalid => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    "Auth token invalid",
                    sentry::Level::Warning,
                );
                ApiError::AuthToken
            }
            Error::FirebaseApiErr(e) => {
                crate::sentry_utils::add_firebase_breadcrumb("error", e, false);
                ApiError::FirebaseApiError(e.clone())
            }
            Error::BackendAdminIdentityInvalid(e) => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    &format!("Backend admin identity invalid: {}", e),
                    sentry::Level::Error,
                );
                ApiError::BackendAdminIdentityInvalid(e.clone())
            }
            Error::Unknown(e) => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    &format!("Unknown error: {}", e),
                    sentry::Level::Error,
                );
                ApiError::Unknown(e.clone())
            }
            Error::EnvironmentVariable(_) => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    "Environment variable error",
                    sentry::Level::Error,
                );
                ApiError::EnvironmentVariable
            }
            Error::EnvironmentVariableMissing(_) => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    "Environment variable missing",
                    sentry::Level::Error,
                );
                ApiError::EnvironmentVariableMissing
            }
            Error::UserAlreadyRegistered(e) => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    &format!("User already registered: {}", e),
                    sentry::Level::Info,
                );
                ApiError::UserAlreadyRegistered(e.clone())
            }
            Error::InvalidPrincipal(_) => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    "Invalid principal",
                    sentry::Level::Warning,
                );
                ApiError::InvalidPrincipal
            }
            Error::Agent(e) => {
                log::warn!("agent error {e}");
                crate::sentry_utils::add_canister_call_breadcrumb("unknown", "agent_error", false);
                ApiError::Unknown(e.to_string())
            }
            Error::UpdateSession(e) => {
                log::warn!("update session error {e}");
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    &format!("Update session error: {}", e),
                    sentry::Level::Error,
                );
                ApiError::UpdateSession(e.clone())
            }
            Error::SwaggerUi(e) => {
                log::warn!("swagger ui error {e}");
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    &format!("Swagger UI error: {}", e),
                    sentry::Level::Error,
                );
                ApiError::Unknown(format!("Swagger UI error: {}", e))
            }
            Error::InvalidUsername => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    "Invalid username",
                    sentry::Level::Warning,
                );
                ApiError::InvalidUsername
            }
            Error::InvalidEmail(email) => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    &format!("Invalid email: {}", email),
                    sentry::Level::Warning,
                );
                ApiError::InvalidEmail(email.clone())
            }
            Error::DuplicateUsername => {
                crate::sentry_utils::add_operation_breadcrumb(
                    "error",
                    "Duplicate username",
                    sentry::Level::Warning,
                );
                ApiError::DuplicateUsername
            }
        };
        ApiResult::Err(err)
    }
}

// Implement IntoResponse for axum error handling
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let api_error = ApiResult::from(&self);
        let status_code = self.status_code();

        (status_code, Json(api_error)).into_response()
    }
}

impl Error {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Error::IO(_)
            | Error::Config(_)
            | Error::Redis(_)
            | Error::Deser(_)
            | Error::Bb8(_)
            | Error::FirebaseApiErr(_)
            | Error::Unknown(_)
            | Error::BackendAdminIdentityInvalid(_)
            | Error::Agent(_)
            | Error::UpdateSession(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Identity(_)
            | Error::Jwt(_)
            | Error::AuthTokenInvalid
            | Error::AuthTokenMissing => StatusCode::UNAUTHORIZED,
            Error::EnvironmentVariable(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::EnvironmentVariableMissing(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::UserAlreadyRegistered(_)
            | Error::InvalidPrincipal(_)
            | Error::InvalidEmail(_)
            | Error::InvalidUsername => StatusCode::BAD_REQUEST,
            Error::SwaggerUi(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::DuplicateUsername => StatusCode::CONFLICT,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
