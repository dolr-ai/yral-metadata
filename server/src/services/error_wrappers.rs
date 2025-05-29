use std::{env::VarError, ops::Deref};

use ic_agent::export::PrincipalError;
use redis::RedisError;
// Add necessary imports
use serde::Serialize;
// Assuming these crates are available in the project
use bb8;
use config;
use jsonwebtoken::errors as jwt_errors;
use serde_json;
use thiserror::Error;
use utoipa::ToSchema;
use yral_identity;

// Define detailed error structs

#[derive(Debug, ToSchema, Serialize)]
pub struct IoErrorDetail {
    #[schema(example = "NotFound")]
    pub kind: String,
    #[schema(example = "File not found")]
    pub message: String,
}

impl From<std::io::Error> for IoErrorDetail {
    fn from(e: std::io::Error) -> Self {
        Self {
            kind: e.kind().to_string(),
            message: e.to_string(),
        }
    }
}

#[derive(Debug, ToSchema, Serialize)]
pub enum ConfigErrorDetail {
    #[schema(example = "Configuration is frozen and no further mutations can be made.")]
    Frozen,

    #[schema(example = "Configuration property was not found")]
    NotFound(String),

    #[schema(example = "Configuration path could not be parsed.")]
    PathParse(String),

    FileParse {
        #[schema(example = "/path/to/config.json")]
        uri: Option<String>,
        #[schema(example = "EOF while parsing a value")]
        cause: String,
    },

    Type {
        #[schema(example = "/path/to/config.json")]
        origin: Option<String>,

        #[schema(example = "EOF while parsing a value")]
        unexpected: String,

        #[schema(example = "String")]
        expected: &'static str,

        #[schema(example = "key")]
        key: Option<String>,
    },

    Message(String),

    Foreign(String),
}

impl From<config::ConfigError> for ConfigErrorDetail {
    fn from(e: config::ConfigError) -> Self {
        match e {
            config::ConfigError::Frozen => ConfigErrorDetail::Frozen,
            config::ConfigError::NotFound(s) => ConfigErrorDetail::NotFound(s),
            config::ConfigError::PathParse(s) => ConfigErrorDetail::PathParse(format!("{:?}", s)),
            config::ConfigError::FileParse { uri, cause } => ConfigErrorDetail::FileParse {
                uri,
                cause: cause.to_string(),
            },
            config::ConfigError::Type {
                origin,
                unexpected,
                expected,
                key,
            } => ConfigErrorDetail::Type {
                origin,
                unexpected: unexpected.to_string(),
                expected,
                key,
            },
            config::ConfigError::Message(s) => ConfigErrorDetail::Message(s),
            config::ConfigError::Foreign(e) => ConfigErrorDetail::Foreign(e.to_string()),
        }
    }
}

#[derive(Debug, ToSchema, Serialize)]
pub struct IdentityErrorDetail {
    #[schema(example = "Signature verification failed")]
    pub message: String,
}

impl From<yral_identity::Error> for IdentityErrorDetail {
    fn from(e: yral_identity::Error) -> Self {
        Self {
            message: e.to_string(),
        }
    }
}

impl std::fmt::Display for IdentityErrorDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Debug, ToSchema, Serialize)]
pub struct RedisErrorDetail {
    #[schema(example = "ResponseError")]
    pub kind: RedisErrorKind,
    #[schema(example = "Connection refused")]
    pub detail: String,
}

#[derive(Debug, ToSchema, Serialize)]
pub enum RedisErrorKind {
    ResponseError,
    ParseError,
    AuthenticationFailed,
    TypeError,
    ExecAbortError,
    BusyLoadingError,
    NoScriptError,
    InvalidClientConfig,
    Moved,
    Ask,
    TryAgain,
    ClusterDown,
    CrossSlot,
    MasterDown,
    IoError,
    ClientError,
    ExtensionError,
    ReadOnly,
    MasterNameNotFoundBySentinel,
    NoValidReplicasFoundBySentinel,
    EmptySentinelList,
    NotBusy,
    ClusterConnectionNotFound,
    Unknown,
}

impl From<redis::ErrorKind> for RedisErrorKind {
    fn from(e: redis::ErrorKind) -> Self {
        match e {
            redis::ErrorKind::ResponseError => RedisErrorKind::ResponseError,
            redis::ErrorKind::ParseError => RedisErrorKind::ParseError,
            redis::ErrorKind::AuthenticationFailed => RedisErrorKind::AuthenticationFailed,
            redis::ErrorKind::TypeError => RedisErrorKind::TypeError,
            redis::ErrorKind::ExecAbortError => RedisErrorKind::ExecAbortError,
            redis::ErrorKind::BusyLoadingError => RedisErrorKind::BusyLoadingError,
            redis::ErrorKind::NoScriptError => RedisErrorKind::NoScriptError,
            redis::ErrorKind::InvalidClientConfig => RedisErrorKind::InvalidClientConfig,
            redis::ErrorKind::Moved => RedisErrorKind::Moved,
            redis::ErrorKind::Ask => RedisErrorKind::Ask,
            redis::ErrorKind::TryAgain => RedisErrorKind::TryAgain,
            redis::ErrorKind::ClusterDown => RedisErrorKind::ClusterDown,
            redis::ErrorKind::CrossSlot => RedisErrorKind::CrossSlot,
            redis::ErrorKind::MasterDown => RedisErrorKind::MasterDown,
            redis::ErrorKind::IoError => RedisErrorKind::IoError,
            redis::ErrorKind::ClientError => RedisErrorKind::ClientError,
            redis::ErrorKind::ExtensionError => RedisErrorKind::ExtensionError,
            redis::ErrorKind::ReadOnly => RedisErrorKind::ReadOnly,
            redis::ErrorKind::MasterNameNotFoundBySentinel => {
                RedisErrorKind::MasterNameNotFoundBySentinel
            }
            redis::ErrorKind::NoValidReplicasFoundBySentinel => {
                RedisErrorKind::NoValidReplicasFoundBySentinel
            }
            redis::ErrorKind::EmptySentinelList => RedisErrorKind::EmptySentinelList,
            redis::ErrorKind::ClusterConnectionNotFound => {
                RedisErrorKind::ClusterConnectionNotFound
            }
            redis::ErrorKind::NotBusy => RedisErrorKind::NotBusy,
            _ => RedisErrorKind::Unknown,
        }
    }
}

impl From<RedisError> for RedisErrorDetail {
    fn from(e: RedisError) -> Self {
        Self {
            kind: RedisErrorKind::from(e.kind()),
            detail: e.to_string(),
        }
    }
}

#[derive(Debug, ToSchema, Serialize)]
#[serde(tag = "type", content = "payload")]
pub enum Bb8RedisErrorDetail {
    Timeout,
    User(RedisErrorDetail),
}

impl From<bb8::RunError<RedisError>> for Bb8RedisErrorDetail {
    fn from(e: bb8::RunError<RedisError>) -> Self {
        match e {
            bb8::RunError::TimedOut => Bb8RedisErrorDetail::Timeout,
            bb8::RunError::User(redis_err) => {
                Bb8RedisErrorDetail::User(RedisErrorDetail::from(redis_err))
            }
        }
    }
}

#[derive(Debug, ToSchema, Serialize)]
pub struct SerdeJsonErrorDetail {
    #[schema(example = 1)]
    pub line: usize,
    #[schema(example = 1)]
    pub column: usize,
    #[schema(example = "EOF while parsing a value")]
    pub message: String,
}

impl From<serde_json::Error> for SerdeJsonErrorDetail {
    fn from(e: serde_json::Error) -> Self {
        Self {
            line: e.line(),
            column: e.column(),
            message: e.to_string(),
        }
    }
}

impl From<&serde_json::Error> for SerdeJsonErrorDetail {
    fn from(e: &serde_json::Error) -> Self {
        Self {
            line: e.line(),
            column: e.column(),
            message: e.to_string(),
        }
    }
}

impl std::fmt::Display for SerdeJsonErrorDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "line {} column {}: {}",
            self.line, self.column, self.message
        )
    }
}

#[derive(Debug, ToSchema, Serialize)]
pub struct JwtErrorDetail {
    pub kind: JwtErrorKind,
    #[schema(example = "Expired token")]
    pub message: String,
}

#[derive(Debug, ToSchema, Serialize)]
pub enum JwtErrorKind {
    #[schema(example = "When a token doesn't have a valid JWT shape")]
    InvalidToken,
    #[schema(example = "When the signature doesn't match")]
    InvalidSignature,
    #[schema(example = "When the secret given is not a valid ECDSA key")]
    InvalidEcdsaKey,
    #[schema(example = "When the secret given is not a valid RSA key")]
    InvalidRsaKey(String),
    #[schema(example = "We could not sign with the given key")]
    RsaFailedSigning,
    #[schema(
        example = "When the algorithm from string doesn't match the one passed to `from_str`"
    )]
    InvalidAlgorithmName,
    #[schema(example = "When a key is provided with an invalid format")]
    InvalidKeyFormat,

    #[schema(example = "When a claim required by the validation is not present")]
    MissingRequiredClaim(String),
    #[schema(example = "When a token's `exp` claim indicates that it has expired")]
    ExpiredSignature,
    #[schema(example = "When a token's `iss` claim does not match the expected issuer")]
    InvalidIssuer,
    #[schema(
        example = "When a token's `aud` claim does not match one of the expected audience values"
    )]
    InvalidAudience,
    #[schema(
        example = "When a token's `sub` claim does not match one of the expected subject values"
    )]
    InvalidSubject,
    #[schema(example = "When a token's `nbf` claim represents a time in the future")]
    ImmatureSignature,
    #[schema(
        example = "When the algorithm in the header doesn't match the one passed to `decode` or the encoding/decoding key used doesn't match the alg requested"
    )]
    InvalidAlgorithm,
    #[schema(example = "When the Validation struct does not contain at least 1 algorithm")]
    MissingAlgorithm,

    #[schema(example = "An error happened when decoding some base64 text")]
    Base64(String),
    #[schema(example = "An error happened while serializing/deserializing JSON")]
    Json(SerdeJsonErrorDetail),
    #[schema(example = "Some of the text was invalid UTF-8")]
    Utf8(String),
    #[schema(example = "Something unspecified went wrong with crypto")]
    Crypto(String),
    #[schema(example = "Unknown error")]
    Unknown,
}

impl From<&jwt_errors::ErrorKind> for JwtErrorKind {
    fn from(e: &jwt_errors::ErrorKind) -> Self {
        match e {
            jwt_errors::ErrorKind::InvalidToken => JwtErrorKind::InvalidToken,
            jwt_errors::ErrorKind::InvalidSignature => JwtErrorKind::InvalidSignature,
            jwt_errors::ErrorKind::InvalidEcdsaKey => JwtErrorKind::InvalidEcdsaKey,
            jwt_errors::ErrorKind::InvalidRsaKey(e) => JwtErrorKind::InvalidRsaKey(e.to_string()),
            jwt_errors::ErrorKind::RsaFailedSigning => JwtErrorKind::RsaFailedSigning,
            jwt_errors::ErrorKind::InvalidAlgorithmName => JwtErrorKind::InvalidAlgorithmName,
            jwt_errors::ErrorKind::InvalidKeyFormat => JwtErrorKind::InvalidKeyFormat,
            jwt_errors::ErrorKind::MissingRequiredClaim(e) => {
                JwtErrorKind::MissingRequiredClaim(e.to_string())
            }
            jwt_errors::ErrorKind::ExpiredSignature => JwtErrorKind::ExpiredSignature,
            jwt_errors::ErrorKind::InvalidIssuer => JwtErrorKind::InvalidIssuer,
            jwt_errors::ErrorKind::InvalidAudience => JwtErrorKind::InvalidAudience,
            jwt_errors::ErrorKind::InvalidSubject => JwtErrorKind::InvalidSubject,
            jwt_errors::ErrorKind::ImmatureSignature => JwtErrorKind::ImmatureSignature,
            jwt_errors::ErrorKind::InvalidAlgorithm => JwtErrorKind::InvalidAlgorithm,
            jwt_errors::ErrorKind::MissingAlgorithm => JwtErrorKind::MissingAlgorithm,
            jwt_errors::ErrorKind::Base64(e) => JwtErrorKind::Base64(e.to_string()),
            jwt_errors::ErrorKind::Json(e) => {
                JwtErrorKind::Json(SerdeJsonErrorDetail::from(e.deref()))
            }
            jwt_errors::ErrorKind::Utf8(e) => JwtErrorKind::Utf8(e.to_string()),
            jwt_errors::ErrorKind::Crypto(e) => JwtErrorKind::Crypto(e.to_string()),
            _ => JwtErrorKind::Unknown,
        }
    }
}
impl From<jwt_errors::Error> for JwtErrorDetail {
    fn from(e: jwt_errors::Error) -> Self {
        Self {
            kind: JwtErrorKind::from(e.kind()),
            message: e.to_string(),
        }
    }
}

#[derive(Debug, ToSchema, Serialize)]
#[serde(tag = "type")]
pub enum VarErrorDetail {
    #[schema(example = "Environment variable not present")]
    NotPresent,
    NotUnicode {
        #[schema(example = "some_value")]
        original_value_lossy: String,
    },
}

impl From<VarError> for VarErrorDetail {
    fn from(e: VarError) -> Self {
        match e {
            VarError::NotPresent => VarErrorDetail::NotPresent,
            VarError::NotUnicode(os_string) => VarErrorDetail::NotUnicode {
                original_value_lossy: os_string.to_string_lossy().into_owned(),
            },
        }
    }
}

#[derive(Debug, ToSchema, Serialize, Error)]
pub enum PrincipalErrorDetail {
    #[error("Bytes is longer than 29 bytes.")]
    #[schema(example = "Bytes is longer than 29 bytes.")]
    BytesTooLong,

    #[error("Text must be in valid Base32 encoding.")]
    #[schema(example = "Text must be in valid Base32 encoding.")]
    InvalidBase32,

    #[error("Text is too short.")]
    #[schema(example = "Text is too short.")]
    TextTooShort,

    #[error("Text is too long.")]
    #[schema(example = "Text is too long.")]
    TextTooLong,

    #[error("CRC32 check sequence doesn't match with calculated from Principal bytes.")]
    #[schema(example = "CRC32 check sequence doesn't match with calculated from Principal bytes.")]
    CheckSequenceNotMatch,

    #[error(r#"Text should be separated by - (dash) every 5 characters: expected "{0}""#)]
    #[schema(
        example = "Text should be separated by - (dash) every 5 characters: expected \"12345-67890\""
    )]
    AbnormalGrouped(String),
}

impl From<PrincipalError> for PrincipalErrorDetail {
    fn from(e: PrincipalError) -> Self {
        match e {
            PrincipalError::BytesTooLong() => PrincipalErrorDetail::BytesTooLong,
            PrincipalError::InvalidBase32() => PrincipalErrorDetail::InvalidBase32,
            PrincipalError::TextTooShort() => PrincipalErrorDetail::TextTooShort,
            PrincipalError::TextTooLong() => PrincipalErrorDetail::TextTooLong,
            PrincipalError::CheckSequenceNotMatch() => PrincipalErrorDetail::CheckSequenceNotMatch,
            PrincipalError::AbnormalGrouped(principal) => {
                PrincipalErrorDetail::AbnormalGrouped(principal.to_text())
            }
        }
    }
}

#[derive(Debug, ToSchema, Serialize)]
pub struct AgentErrorDetail {
    #[schema(example = "InvalidReplicaUrl")]
    pub kind: String,
    #[schema(example = "Invalid Replica URL: \"https://replica.example.com\"")]
    pub message: String,
}

impl From<ic_agent::AgentError> for AgentErrorDetail {
    fn from(e: ic_agent::AgentError) -> Self {
        match e {
            ic_agent::AgentError::InvalidReplicaUrl(url) => AgentErrorDetail {
                kind: "InvalidReplicaUrl".to_string(),
                message: format!("Invalid Replica URL: \"{}\"", url),
            },
            ic_agent::AgentError::TimeoutWaitingForResponse() => AgentErrorDetail {
                kind: "TimeoutWaitingForResponse".to_string(),
                message: "The request timed out while waiting for a response.".to_string(),
            },
            ic_agent::AgentError::SigningError(error) => AgentErrorDetail {
                kind: "SigningError".to_string(),
                message: format!("Identity had a signing error: \"{}\"", error),
            },
            ic_agent::AgentError::InvalidCborData(error) => AgentErrorDetail {
                kind: "InvalidCborData".to_string(),
                message: format!("Invalid CBOR data, could not deserialize: \"{}\"", error.to_string()),
            },
            ic_agent::AgentError::CannotCalculateRequestId(error) => AgentErrorDetail {
                kind: "CannotCalculateRequestId".to_string(),
                message: format!("Cannot calculate a RequestID: \"{}\"", error.to_string()),
            },
            ic_agent::AgentError::CandidError(error) => AgentErrorDetail {
                kind: "CandidError".to_string(),
                message: format!("Candid returned an error: \"{}\"", error.to_string()),
            },
            ic_agent::AgentError::UrlParseError(error) => AgentErrorDetail {
                kind: "UrlParseError".to_string(),
                message: format!("Cannot parse url: \"{}\"", error.to_string()),
            },
            ic_agent::AgentError::InvalidMethodError(error) => AgentErrorDetail {
                kind: "InvalidMethodError".to_string(),
                message: format!("Invalid method: \"{}\"", error.to_string()),
            },
            ic_agent::AgentError::PrincipalError(error) => AgentErrorDetail {
                kind: "PrincipalError".to_string(),
                message: format!("Cannot parse Principal: \"{}\"", error.to_string()),
            },
            ic_agent::AgentError::CertifiedReject(error) => AgentErrorDetail {
                kind: "CertifiedReject".to_string(),
                message: format!("The replica returned a certified rejection error: {:?}", error),
            },
            ic_agent::AgentError::UncertifiedReject(error) => AgentErrorDetail {
                kind: "UncertifiedReject".to_string(),
                message: format!("The replica returned an uncertified rejection error: {:?}", error),
            },
            ic_agent::AgentError::HttpError(error) => AgentErrorDetail {
                kind: "HttpError".to_string(),
                message: format!("The replica returned an HTTP Error: {:?}", error),
            },
            ic_agent::AgentError::InvalidReplicaStatus => AgentErrorDetail {
                kind: "InvalidReplicaStatus".to_string(),
                message: "Status endpoint returned an invalid status.".to_string(),
            },
            ic_agent::AgentError::RequestStatusDoneNoReply(request_id) => AgentErrorDetail {
                kind: "RequestStatusDoneNoReply".to_string(),
                message: format!("Call was marked as done but we never saw the reply. Request ID: \"{}\"", request_id),
            },
            ic_agent::AgentError::MessageError(msg) => AgentErrorDetail {
                kind: "MessageError".to_string(),
                message: format!("A tool returned a string message error: \"{}\"", msg),
            },
            ic_agent::AgentError::Leb128ReadError(error) => AgentErrorDetail {
                kind: "Leb128ReadError".to_string(),
                message: format!("Error reading LEB128 value: \"{}\"", error.to_string()),
            },
            ic_agent::AgentError::Utf8ReadError(error) => AgentErrorDetail {
                kind: "Utf8ReadError".to_string(),
                message: format!("Error in UTF-8 string: \"{}\"", error.to_string()),
            },
            ic_agent::AgentError::LookupPathAbsent(path) => AgentErrorDetail {
                kind: "LookupPathAbsent".to_string(),
                message: format!("The lookup path ({:?}) is absent in the certificate.", path),
            },
            ic_agent::AgentError::LookupPathUnknown(path) => AgentErrorDetail {
                kind: "LookupPathUnknown".to_string(),
                message: format!("The lookup path ({:?}) is unknown in the certificate.", path),
            },
            ic_agent::AgentError::LookupPathError(path) => AgentErrorDetail {
                kind: "LookupPathError".to_string(),
                message: format!("The lookup path ({:?}) does not make sense for the certificate.", path),
            },
            ic_agent::AgentError::InvalidRequestStatus(status, path) => AgentErrorDetail {
                kind: "InvalidRequestStatus".to_string(),
                message: format!("The request status ({:?}) at path ({:?}) is invalid.", status, path),
            },
            ic_agent::AgentError::CertificateVerificationFailed() => AgentErrorDetail {
                kind: "CertificateVerificationFailed".to_string(),
                message: "Certificate verification failed.".to_string(),
            },
            ic_agent::AgentError::QuerySignatureVerificationFailed => AgentErrorDetail {
                kind: "QuerySignatureVerificationFailed".to_string(),
                message: "Query signature verification failed.".to_string(),
            },
            ic_agent::AgentError::CertificateNotAuthorized() => AgentErrorDetail {
                kind: "CertificateNotAuthorized".to_string(),
                message: "Certificate is not authorized to respond to queries for this canister. While developing: Did you forget to set effective_canister_id?".to_string(),
            },
            ic_agent::AgentError::CertificateOutdated(duration) => AgentErrorDetail {
                kind: "CertificateOutdated".to_string(),
                message: format!("Certificate is stale (over {:?}). Is the computer's clock synchronized?", duration),
            },
            ic_agent::AgentError::CertificateHasTooManyDelegations => AgentErrorDetail {
                kind: "CertificateHasTooManyDelegations".to_string(),
                message: "The certificate contained more than one delegation.".to_string(),
            },
            ic_agent::AgentError::MissingSignature => AgentErrorDetail {
                kind: "MissingSignature".to_string(),
                message: "Query response did not contain any node signatures.".to_string(),
            },
            ic_agent::AgentError::MalformedSignature => AgentErrorDetail {
                kind: "MalformedSignature".to_string(),
                message: "Query response contained a malformed signature.".to_string(),
            },
            ic_agent::AgentError::MalformedPublicKey => AgentErrorDetail {
                kind: "MalformedPublicKey".to_string(),
                message: "Read state response contained a malformed public key.".to_string(),
            },
            ic_agent::AgentError::TooManySignatures { had, needed } => AgentErrorDetail {
                kind: "TooManySignatures".to_string(),
                message: format!("Query response contained too many signatures (had {}, exceeding the subnet's total nodes: {}).", had, needed),
            },
            ic_agent::AgentError::DerKeyLengthMismatch { expected, actual } => AgentErrorDetail {
                kind: "DerKeyLengthMismatch".to_string(),
                message: format!("BLS DER-encoded public key must be {} bytes long, but is {} bytes long.", expected, actual),
            },
            ic_agent::AgentError::DerPrefixMismatch { expected, actual } => AgentErrorDetail {
                kind: "DerPrefixMismatch".to_string(),
                message: format!("BLS DER-encoded public key is invalid. Expected the following prefix: {:?}, but got {:?}", expected, actual),
            },
            ic_agent::AgentError::NoRootKeyInStatus(status_string) => AgentErrorDetail {
                kind: "NoRootKeyInStatus".to_string(),
                message: format!("The status response did not contain a root key. Status: \"{}\"", status_string.to_string()),
            },
            ic_agent::AgentError::WalletCallFailed(error_string) => AgentErrorDetail {
                kind: "WalletCallFailed".to_string(),
                message: format!("The invocation to the wallet call forward method failed with the error: \"{}\"", error_string),
            },
            ic_agent::AgentError::WalletError(error_string) => AgentErrorDetail {
                kind: "WalletError".to_string(),
                message: format!("The wallet operation failed: \"{}\"", error_string),
            },
            ic_agent::AgentError::WalletUpgradeRequired(error_string) => AgentErrorDetail {
                kind: "WalletUpgradeRequired".to_string(),
                message: format!("The wallet canister must be upgraded: \"{}\"", error_string),
            },
            ic_agent::AgentError::ResponseSizeExceededLimit() => AgentErrorDetail {
                kind: "ResponseSizeExceededLimit".to_string(),
                message: "Response size exceeded limit.".to_string(),
            },
            ic_agent::AgentError::TransportError(transport_error) => AgentErrorDetail {
                kind: "TransportError".to_string(),
                message: format!("An error happened during communication with the replica: \"{}\"", transport_error.to_string()),
            },
            ic_agent::AgentError::CallDataMismatch {
                field,
                value_arg,
                value_cbor,
            } => AgentErrorDetail {
                kind: "CallDataMismatch".to_string(),
                message: format!(
                    "There is a mismatch between the CBOR encoded call and the arguments: field \"{}\", value in argument is \"{}\", value in CBOR is \"{}\"",
                    field, value_arg, value_cbor
                ),
            },
            ic_agent::AgentError::InvalidRejectCode(reject_code_val) => AgentErrorDetail {
                kind: "InvalidRejectCode".to_string(),
                message: format!("The rejected call had an invalid reject code {}. Valid range is 1-5.", reject_code_val.to_string()),
            },
            ic_agent::AgentError::RouteProviderError(error_string) => AgentErrorDetail {
                kind: "RouteProviderError".to_string(),
                message: format!("Route provider failed to generate url: \"{}\"", error_string),
            },
            ic_agent::AgentError::InvalidHttpResponse(response_string) => AgentErrorDetail {
                kind: "InvalidHttpResponse".to_string(),
                message: format!("Invalid HTTP response: \"{}\"", response_string),
            },
        }
    }
}

#[derive(Debug, ToSchema)]
pub enum IOErrorData {
    #[schema(example = "Os(\"Invalid OS error\")")]
    Os(String),
    #[schema(example = "Simple(\"Invalid simple error\")")]
    Simple(String),
    #[schema(example = "SimpleMessage(\"Invalid simple message error\")")]
    SimpleMessage(String),
    #[schema(example = "Custom(\"Invalid custom error\")")]
    Custom(String),
}
