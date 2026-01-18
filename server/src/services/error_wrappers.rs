use std::{env::VarError, ops::Deref};

use ic_agent::export::PrincipalError;
use redis::RedisError;
// Add necessary imports
use serde::{Deserialize, Serialize};
// Assuming these crates are available in the project
use bb8;
use config;
use jsonwebtoken::errors as jwt_errors;
use serde_json;
use utoipa::ToSchema;
use yral_identity;

// Define detailed error structs
#[allow(non_snake_case)]
#[derive(Debug, ToSchema, Serialize, Deserialize)]
pub struct ErrorWrapper<T: ToSchema> {
    Err: T,
}

#[derive(Debug, ToSchema, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct OkWrapper<T: ToSchema> {
    Ok: T,
}

#[derive(Debug, ToSchema, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct NullOk {
    Ok: (),
}

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
pub struct ConfigErrorDetail {
    #[schema(example = "Frozen")]
    pub kind: String,
    #[schema(example = "Configuration is frozen and no further mutations can be made.")]
    pub message: String,
}

impl From<config::ConfigError> for ConfigErrorDetail {
    fn from(e: config::ConfigError) -> Self {
        match e {
            config::ConfigError::Frozen => ConfigErrorDetail {
                kind: "Frozen".to_string(),
                message: "Configuration is frozen and no further mutations can be made.".to_string(),
            },
            config::ConfigError::NotFound(s) => ConfigErrorDetail {
                kind: "NotFound".to_string(),
                message: format!("Configuration property not found: {}", s),
            },
            config::ConfigError::PathParse(s) => ConfigErrorDetail {
                kind: "PathParse".to_string(),
                message: format!("Configuration path could not be parsed: {:?}", s),
            },
            config::ConfigError::FileParse { uri, cause } => ConfigErrorDetail {
                kind: "FileParse".to_string(),
                message: format!(
                    "Configuration file could not be parsed. URI: {:?}, Cause: {}",
                    uri,
                    cause.to_string()
                ),
            },
            config::ConfigError::Type {
                origin,
                unexpected,
                expected,
                key,
            } => ConfigErrorDetail {
                kind: "Type".to_string(),
                message: format!(
                    "Configuration type error. Origin: {:?}, Unexpected: {}, Expected: {}, Key: {:?}",
                    origin,
                    unexpected.to_string(),
                    expected,
                    key
                ),
            },
            config::ConfigError::Message(s) => ConfigErrorDetail {
                kind: "Message".to_string(),
                message: s,
            },
            config::ConfigError::Foreign(e) => ConfigErrorDetail {
                kind: "Foreign".to_string(),
                message: format!("Foreign error: {}", e.to_string()),
            },
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
            redis::ErrorKind::AuthenticationFailed => RedisErrorKind::AuthenticationFailed,
            redis::ErrorKind::InvalidClientConfig => RedisErrorKind::InvalidClientConfig,
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
pub struct Bb8RedisErrorDetail {
    #[schema(example = "Timeout")]
    pub kind: String,
    #[schema(example = "Connection timed out")]
    pub message: String,
}

impl From<bb8::RunError<RedisError>> for Bb8RedisErrorDetail {
    fn from(e: bb8::RunError<RedisError>) -> Self {
        match e {
            bb8::RunError::TimedOut => Bb8RedisErrorDetail {
                kind: "Timeout".to_string(),
                message: "Connection pool timeout".to_string(),
            },
            bb8::RunError::User(redis_err) => {
                let detail = RedisErrorDetail::from(redis_err);
                Bb8RedisErrorDetail {
                    kind: format!("UserError.{:?}", detail.kind),
                    message: detail.detail,
                }
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
    #[schema(example = "InvalidToken")]
    pub kind: String,
    #[schema(example = "Expired token")]
    pub message: String,
}

impl From<jwt_errors::Error> for JwtErrorDetail {
    fn from(e: jwt_errors::Error) -> Self {
        let kind_str = match e.kind() {
            jwt_errors::ErrorKind::InvalidToken => "InvalidToken".to_string(),
            jwt_errors::ErrorKind::InvalidSignature => "InvalidSignature".to_string(),
            jwt_errors::ErrorKind::InvalidEcdsaKey => "InvalidEcdsaKey".to_string(),
            jwt_errors::ErrorKind::InvalidRsaKey(err) => format!("InvalidRsaKey: {}", err),
            jwt_errors::ErrorKind::RsaFailedSigning => "RsaFailedSigning".to_string(),
            jwt_errors::ErrorKind::InvalidAlgorithmName => "InvalidAlgorithmName".to_string(),
            jwt_errors::ErrorKind::InvalidKeyFormat => "InvalidKeyFormat".to_string(),
            jwt_errors::ErrorKind::MissingRequiredClaim(claim) => {
                format!("MissingRequiredClaim: {}", claim)
            }
            jwt_errors::ErrorKind::ExpiredSignature => "ExpiredSignature".to_string(),
            jwt_errors::ErrorKind::InvalidIssuer => "InvalidIssuer".to_string(),
            jwt_errors::ErrorKind::InvalidAudience => "InvalidAudience".to_string(),
            jwt_errors::ErrorKind::InvalidSubject => "InvalidSubject".to_string(),
            jwt_errors::ErrorKind::ImmatureSignature => "ImmatureSignature".to_string(),
            jwt_errors::ErrorKind::InvalidAlgorithm => "InvalidAlgorithm".to_string(),
            jwt_errors::ErrorKind::MissingAlgorithm => "MissingAlgorithm".to_string(),
            jwt_errors::ErrorKind::Base64(err) => format!("Base64: {}", err),
            jwt_errors::ErrorKind::Json(json_err) => {
                format!("Json: {}", SerdeJsonErrorDetail::from(json_err.deref()))
            }
            jwt_errors::ErrorKind::Utf8(err) => format!("Utf8: {}", err),
            jwt_errors::ErrorKind::Crypto(err) => format!("Crypto: {}", err),
            _ => "Unknown".to_string(),
        };
        Self {
            kind: kind_str,
            message: e.to_string(),
        }
    }
}

#[derive(Debug, ToSchema, Serialize)]
pub struct VarErrorDetail {
    #[schema(example = "NotPresent")]
    pub kind: String,
    #[schema(example = "Environment variable not present, or not unicode")]
    pub message: String,
}

impl From<VarError> for VarErrorDetail {
    fn from(e: VarError) -> Self {
        match e {
            VarError::NotPresent => VarErrorDetail {
                kind: "NotPresent".to_string(),
                message: "Environment variable not present".to_string(),
            },
            VarError::NotUnicode(os_string) => VarErrorDetail {
                kind: "NotUnicode".to_string(),
                message: format!(
                    "Environment variable not unicode. Original value (lossy): {}",
                    os_string.to_string_lossy()
                ),
            },
        }
    }
}

#[derive(Debug, ToSchema, Serialize)]
pub struct PrincipalErrorDetail {
    #[schema(example = "BytesTooLong")]
    pub kind: String,
    #[schema(example = "Bytes is longer than 29 bytes.")]
    pub message: String,
}

impl From<PrincipalError> for PrincipalErrorDetail {
    fn from(e: PrincipalError) -> Self {
        match e {
            PrincipalError::BytesTooLong() => PrincipalErrorDetail {
                kind: "BytesTooLong".to_string(),
                message: "Bytes is longer than 29 bytes.".to_string(),
            },
            PrincipalError::InvalidBase32() => PrincipalErrorDetail {
                kind: "InvalidBase32".to_string(),
                message: "Text must be in valid Base32 encoding.".to_string(),
            },
            PrincipalError::TextTooShort() => PrincipalErrorDetail {
                kind: "TextTooShort".to_string(),
                message: "Text is too short.".to_string(),
            },
            PrincipalError::TextTooLong() => PrincipalErrorDetail {
                kind: "TextTooLong".to_string(),
                message: "Text is too long.".to_string(),
            },
            PrincipalError::CheckSequenceNotMatch() => PrincipalErrorDetail {
                kind: "CheckSequenceNotMatch".to_string(),
                message: "CRC32 check sequence doesn't match with calculated from Principal bytes."
                    .to_string(),
            },
            PrincipalError::AbnormalGrouped(principal) => PrincipalErrorDetail {
                kind: "AbnormalGrouped".to_string(),
                message: format!(
                    "Text should be separated by - (dash) every 5 characters: expected \"{}\"",
                    principal.to_text()
                ),
            },
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
            ic_agent::AgentError::CertifiedReject { reject, .. } => AgentErrorDetail {
                kind: "CertifiedReject".to_string(),
                message: format!("The replica returned a certified rejection error: {:?}", reject.reject_message),
            },
            ic_agent::AgentError::UncertifiedReject { reject, .. } => AgentErrorDetail {
                kind: "UncertifiedReject".to_string(),
                message: format!("The replica returned an uncertified rejection error: {:?}", reject.reject_message),
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
