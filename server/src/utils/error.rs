use ic_agent::export::PrincipalError;
use ntex::{
    http::{header, StatusCode},
    web,
};
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
    #[error("{0}")]
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
}

impl From<&Error> for ApiResult<()> {
    fn from(value: &Error) -> Self {
        let err = match value {
            Error::IO(_) | Error::Config(_) => {
                log::warn!("internal error {value}");
                ApiError::Unknown("internal error, reported".into())
            }
            Error::Identity(_) => ApiError::InvalidSignature,
            Error::Redis(e) => {
                log::warn!("redis error {e}");
                ApiError::Redis
            }
            Error::Bb8(e) => {
                log::warn!("bb8 error {e}");
                ApiError::Redis
            }
            Error::Deser(e) => {
                log::warn!("deserialization error {e}");
                ApiError::Deser
            }
            Error::Jwt(_) => ApiError::Jwt,
            Error::AuthTokenMissing => ApiError::AuthTokenMissing,
            Error::AuthTokenInvalid => ApiError::AuthToken,
            Error::FirebaseApiErr(e) => ApiError::FirebaseApiError(e.clone()),
            Error::BackendAdminIdentityInvalid(e) => {
                ApiError::BackendAdminIdentityInvalid(e.clone())
            }
            Error::Unknown(e) => ApiError::Unknown(e.clone()),
            Error::EnvironmentVariable(_) => ApiError::EnvironmentVariable,
            Error::EnvironmentVariableMissing(_) => ApiError::EnvironmentVariableMissing,
            Error::UserAlreadyRegistered(e) => ApiError::UserAlreadyRegistered(e.clone()),
            Error::InvalidPrincipal(_) => ApiError::InvalidPrincipal,
            Error::Agent(e) => {
                log::warn!("agent error {e}");
                ApiError::Unknown(e.to_string())
            }
            Error::UpdateSession(e) => {
                log::warn!("update session error {e}");
                ApiError::UpdateSession(e.clone())
            }
            Error::SwaggerUi(e) => {
                log::warn!("swagger ui error {e}");
                ApiError::Unknown(format!("Swagger UI error: {}", e))
            }
        };
        ApiResult::Err(err)
    }
}

impl web::error::WebResponseError for Error {
    fn error_response(&self, _: &web::HttpRequest) -> web::HttpResponse {
        let api_error = ApiResult::from(self);
        web::HttpResponse::build(self.status_code())
            .set_header(header::CONTENT_TYPE, "application/json")
            .json(&api_error)
    }

    fn status_code(&self) -> StatusCode {
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
            Error::UserAlreadyRegistered(_) | Error::InvalidPrincipal(_) => StatusCode::BAD_REQUEST,
            Error::SwaggerUi(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
