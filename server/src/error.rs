use ntex::{
    http::{header, StatusCode},
    web,
};
use redis::RedisError;
use thiserror::Error;
use types::{error::ApiError, ApiResult};

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("failed to load config {0}")]
    Config(#[from] config::ConfigError),
    #[error("{0}")]
    Cloudflare(#[from] gob_cloudflare::Error),
    #[error("{0}")]
    Identity(#[from] yral_identity::Error),
    #[error("{0}")]
    Redis(#[from] RedisError),
    #[error("{0}")]
    Bb8(#[from] bb8::RunError<RedisError>),
    #[error("failed to deserialize json {0}")]
    Deser(serde_json::Error),
}

impl From<&Error> for ApiResult<()> {
    fn from(value: &Error) -> Self {
        let err = match value {
            Error::IO(_) | Error::Config(_) => {
                log::warn!("internal error {value}");
                ApiError::Unknown("internal error, reported".into())
            }
            Error::Identity(_) => ApiError::InvalidSignature,
            Error::Cloudflare(e) => {
                log::warn!("cloudflare error {e}");
                ApiError::Cloudflare
            }
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
            | Error::Cloudflare(_)
            | Error::Redis(_)
            | Error::Deser(_)
            | Error::Bb8(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Identity(_) => StatusCode::UNAUTHORIZED,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
