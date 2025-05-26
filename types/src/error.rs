use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Deserialize, Serialize, Error, Debug, PartialEq)]
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
    #[error("metadata for principal not found")]
    MetadataNotFound,
    #[error("device not found")]
    DeviceNotFound,
    #[error("notification key not found")]
    NotificationKeyNotFound,
    #[error("firebase api error: {0}")]
    FirebaseApiError(String),
    #[error("unknown: {0}")]
    Unknown(String),
    #[error("device already registered")]
    DeviceAlreadyRegistered,
    #[error("unauthorized")]
    Unauthorized,
    #[error("environment variable not found")]
    EnvironmentVariable,
    #[error("environment variable missing")]
    EnvironmentVariableMissing,
    #[error("failed to mark user session as registered: {0}")]
    UserAlreadyRegistered(String),
    #[error("failed to initialize backend admin ic agent: {0}")]
    BackendAdminIdentityInvalid(String),
    #[error("invalid principal")]
    InvalidPrincipal,
    #[error("failed to update session: {0}")]
    UpdateSession(String),
}
