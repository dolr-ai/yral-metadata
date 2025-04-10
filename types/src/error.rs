use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Deserialize, Serialize, Error, Debug)]
#[non_exhaustive]
pub enum ApiError {
    #[error("invalid signature provided")]
    InvalidSignature,
    #[error("internal error: redis")]
    Redis,
    #[error("internal error: deser")]
    Deser,
    #[error("jwt error - invalid token")]
    Jwt,
    #[error("invalid authentication token")]
    AuthToken,
    #[error("missing authentication token")]
    AuthTokenMissing,
    #[error("failed to delete keys (redis)")]
    DeleteKeys,
    #[error("unknown: {0}")]
    Unknown(String),
}
