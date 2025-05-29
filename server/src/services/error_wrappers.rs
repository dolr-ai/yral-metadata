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
pub enum AgentErrorDetail {
    /// The replica URL was invalid.
    #[schema(example = "Invalid Replica URL: \"https://replica.example.com\"")]
    InvalidReplicaUrl(String),

    /// The request timed out.
    #[schema(example = "The request timed out while waiting for a response.")]
    TimeoutWaitingForResponse,

    /// An error occurred when signing with the identity.
    #[schema(example = "Identity had a signing error: \"Invalid signature\"")]
    SigningError(String),

    /// The data fetched was invalid CBOR.
    #[schema(example = "Invalid CBOR data, could not deserialize: \"Invalid CBOR data\"")]
    InvalidCborData(String),

    /// There was an error calculating a request ID.
    #[schema(example = "Cannot calculate a RequestID: \"Invalid request ID\"")]
    CannotCalculateRequestId(String),

    /// There was an error when de/serializing with Candid.
    #[schema(example = "Candid returned an error: \"Invalid candid\"")]
    CandidError(String),

    /// There was an error parsing a URL.
    #[schema(example = "Cannot parse url: \"Invalid URL\"")]
    UrlParseError(String),

    /// The HTTP method was invalid.
    #[schema(example = "Invalid method: \"Invalid method\"")]
    InvalidMethodError(String),

    /// The principal string was not a valid principal.
    #[schema(example = "Cannot parse Principal: \"Invalid principal\"")]
    PrincipalError(String),

    /// The subnet rejected the message.
    #[schema(
        example = "The replica returned a rejection error: reject code 1, reject message \"Reject message\", error code 2"
    )]
    CertifiedReject(String),

    /// The replica rejected the message. This rejection cannot be verified as authentic.
    #[schema(
        example = "The replica returned a rejection error: reject code 1, reject message \"Reject message\", error code 2"
    )]
    UncertifiedReject(String),

    /// The replica returned an HTTP error.
    #[schema(example = "The replica returned an HTTP Error: \"Invalid HTTP error\"")]
    HttpError(String),

    /// The status endpoint returned an invalid status.
    #[schema(example = "Status endpoint returned an invalid status.")]
    InvalidReplicaStatus,

    /// The call was marked done, but no reply was provided.
    #[schema(
        example = "Call was marked as done but we never saw the reply. Request ID: \"Request ID\""
    )]
    RequestStatusDoneNoReply(String),

    /// A string error occurred in an external tool.
    #[schema(example = "A tool returned a string message error: \"Invalid message\"")]
    MessageError(String),

    /// There was an error reading a LEB128 value.
    #[schema(example = "Error reading LEB128 value: \"Invalid LEB128 value\"")]
    Leb128ReadError(String),

    /// A string was invalid UTF-8.
    #[schema(example = "Error in UTF-8 string: \"Invalid UTF-8 string\"")]
    Utf8ReadError(String),

    /// The lookup path was absent in the certificate.
    #[schema(example = "The lookup path (\"path\") is absent in the certificate.")]
    LookupPathAbsent(String),

    /// The lookup path was unknown in the certificate.
    #[schema(example = "The lookup path (\"path\") is unknown in the certificate.")]
    LookupPathUnknown(String),

    /// The lookup path did not make sense for the certificate.
    #[schema(example = "The lookup path (\"path\") does not make sense for the certificate.")]
    LookupPathError(String),

    /// The request status at the requested path was invalid.
    #[schema(example = "The request status (\"status\") at path (\"path\") is invalid.")]
    InvalidRequestStatus(String, String),

    /// The certificate verification for a read_state call failed.
    #[schema(example = "Certificate verification failed.")]
    CertificateVerificationFailed,

    /// The signature verification for a query call failed.
    #[schema(example = "Query signature verification failed.")]
    QuerySignatureVerificationFailed,

    /// The certificate contained a delegation that does not include the effective_canister_id in the canister_ranges field.
    #[schema(
        example = "Certificate is not authorized to respond to queries for this canister. While developing: Did you forget to set effective_canister_id?"
    )]
    CertificateNotAuthorized,

    /// The certificate was older than allowed by the `ingress_expiry`.
    #[schema(
        example = "Certificate is stale (over \"duration\"). Is the computer's clock synchronized?"
    )]
    CertificateOutdated(String),

    /// The certificate contained more than one delegation.
    #[schema(example = "The certificate contained more than one delegation")]
    CertificateHasTooManyDelegations,

    /// The query response did not contain any node signatures.
    #[schema(example = "Query response did not contain any node signatures")]
    MissingSignature,

    /// The query response contained a malformed signature.
    #[schema(example = "Query response contained a malformed signature")]
    MalformedSignature,

    /// The read-state response contained a malformed public key.
    #[schema(example = "Read state response contained a malformed public key")]
    MalformedPublicKey,

    /// The query response contained more node signatures than the subnet has nodes.
    #[schema(
        example = "Query response contained too many signatures (1, exceeding the subnet's total nodes: 2)"
    )]
    TooManySignatures {
        /// The number of provided signatures.
        had: usize,
        /// The number of nodes on the subnet.
        needed: usize,
    },

    /// There was a length mismatch between the expected and actual length of the BLS DER-encoded public key.
    #[schema(example = "BLS DER-encoded public key must be 32 bytes long, but is 33 bytes long.")]
    DerKeyLengthMismatch {
        /// The expected length of the key.
        expected: usize,
        /// The actual length of the key.
        actual: usize,
    },

    /// There was a mismatch between the expected and actual prefix of the BLS DER-encoded public key.
    #[schema(
        example = "BLS DER-encoded public key is invalid. Expected the following prefix: [1, 2, 3], but got [4, 5, 6]"
    )]
    DerPrefixMismatch {
        /// The expected key prefix.
        expected: Vec<u8>,
        /// The actual key prefix.
        actual: Vec<u8>,
    },

    /// The status response did not contain a root key.
    #[schema(example = "The status response did not contain a root key.  Status: \"Status\"")]
    NoRootKeyInStatus(String),

    /// The invocation to the wallet call forward method failed with an error.
    #[schema(
        example = "The invocation to the wallet call forward method failed with the error: \"Invalid error\""
    )]
    WalletCallFailed(String),

    /// The wallet operation failed.
    #[schema(example = "The  wallet operation failed: \"Invalid error\"")]
    WalletError(String),

    /// The wallet canister must be upgraded. See [`dfx wallet upgrade`](https://internetcomputer.org/docs/current/references/cli-reference/dfx-wallet)
    #[schema(example = "The wallet canister must be upgraded: \"Invalid error\"")]
    WalletUpgradeRequired(String),

    /// The response size exceeded the provided limit.
    #[schema(example = "Response size exceeded limit.")]
    ResponseSizeExceededLimit,

    /// An unknown error occurred during communication with the replica.
    #[schema(
        example = "An error happened during communication with the replica: \"Transport error details\""
    )]
    TransportError(String),

    /// There was a mismatch between the expected and actual CBOR data during inspection.
    #[schema(
        example = "There is a mismatch between the CBOR encoded call and the arguments: field \"field\", value in argument is \"value_arg\", value in CBOR is \"value_cbor\""
    )]
    CallDataMismatch {
        /// The field that was mismatched.
        field: String,
        /// The value that was expected to be in the CBOR.
        value_arg: String,
        /// The value that was actually in the CBOR.
        value_cbor: String,
    },

    /// The rejected call had an invalid reject code (valid range 1..5).
    #[schema(example = "The rejected call had an invalid reject code (valid range 1..5).")]
    InvalidRejectCode(String),

    /// Route provider failed to generate a url for some reason.
    #[schema(example = "Route provider failed to generate url: \"Invalid error\"")]
    RouteProviderError(String),

    /// Invalid HTTP response.
    #[schema(example = "Invalid HTTP response: \"Invalid HTTP response\"")]
    InvalidHttpResponse(String),
}

impl From<ic_agent::AgentError> for AgentErrorDetail {
    fn from(e: ic_agent::AgentError) -> Self {
        match e {
            ic_agent::AgentError::InvalidReplicaUrl(url) => {
                AgentErrorDetail::InvalidReplicaUrl(url)
            }
            ic_agent::AgentError::TimeoutWaitingForResponse() => {
                AgentErrorDetail::TimeoutWaitingForResponse
            }
            ic_agent::AgentError::SigningError(error) => AgentErrorDetail::SigningError(error),
            ic_agent::AgentError::InvalidCborData(error) => {
                AgentErrorDetail::InvalidCborData(error.to_string())
            }
            ic_agent::AgentError::CannotCalculateRequestId(error) => {
                AgentErrorDetail::CannotCalculateRequestId(error.to_string())
            }
            ic_agent::AgentError::CandidError(error) => {
                AgentErrorDetail::CandidError(error.to_string())
            }
            ic_agent::AgentError::UrlParseError(error) => {
                AgentErrorDetail::UrlParseError(error.to_string())
            }
            ic_agent::AgentError::InvalidMethodError(error) => {
                AgentErrorDetail::InvalidMethodError(error.to_string())
            }
            ic_agent::AgentError::PrincipalError(error) => {
                AgentErrorDetail::PrincipalError(error.to_string())
            }
            ic_agent::AgentError::CertifiedReject(error) => {
                AgentErrorDetail::CertifiedReject(format!("{:?}", error))
            }
            ic_agent::AgentError::UncertifiedReject(error) => {
                AgentErrorDetail::UncertifiedReject(format!("{:?}", error))
            }
            ic_agent::AgentError::HttpError(error) => {
                AgentErrorDetail::HttpError(format!("{:?}", error))
            }
            ic_agent::AgentError::InvalidReplicaStatus => AgentErrorDetail::InvalidReplicaStatus,
            ic_agent::AgentError::RequestStatusDoneNoReply(error) => {
                AgentErrorDetail::RequestStatusDoneNoReply(error)
            }
            ic_agent::AgentError::MessageError(error) => AgentErrorDetail::MessageError(error),
            ic_agent::AgentError::Leb128ReadError(error) => {
                AgentErrorDetail::Leb128ReadError(error.to_string())
            }
            ic_agent::AgentError::Utf8ReadError(error) => {
                AgentErrorDetail::Utf8ReadError(error.to_string())
            }
            ic_agent::AgentError::LookupPathAbsent(error) => {
                AgentErrorDetail::LookupPathAbsent(format!("{:?}", error))
            }
            ic_agent::AgentError::LookupPathUnknown(error) => {
                AgentErrorDetail::LookupPathUnknown(format!("{:?}", error))
            }
            ic_agent::AgentError::LookupPathError(error) => {
                AgentErrorDetail::LookupPathError(format!("{:?}", error))
            }
            ic_agent::AgentError::InvalidRequestStatus(status, path) => {
                AgentErrorDetail::InvalidRequestStatus(
                    format!("{:?}", status),
                    format!("{:?}", path),
                )
            }
            ic_agent::AgentError::CertificateVerificationFailed() => {
                AgentErrorDetail::CertificateVerificationFailed
            }
            ic_agent::AgentError::QuerySignatureVerificationFailed => {
                AgentErrorDetail::QuerySignatureVerificationFailed
            }
            ic_agent::AgentError::CertificateNotAuthorized() => {
                AgentErrorDetail::CertificateNotAuthorized
            }
            ic_agent::AgentError::CertificateOutdated(duration) => {
                AgentErrorDetail::CertificateOutdated(format!("{:?}", duration))
            }
            ic_agent::AgentError::CertificateHasTooManyDelegations => {
                AgentErrorDetail::CertificateHasTooManyDelegations
            }
            ic_agent::AgentError::MissingSignature => AgentErrorDetail::MissingSignature,
            ic_agent::AgentError::MalformedSignature => AgentErrorDetail::MalformedSignature,
            ic_agent::AgentError::MalformedPublicKey => AgentErrorDetail::MalformedPublicKey,
            ic_agent::AgentError::TooManySignatures { had, needed } => {
                AgentErrorDetail::TooManySignatures { had, needed }
            }
            ic_agent::AgentError::DerKeyLengthMismatch { expected, actual } => {
                AgentErrorDetail::DerKeyLengthMismatch { expected, actual }
            }
            ic_agent::AgentError::DerPrefixMismatch { expected, actual } => {
                AgentErrorDetail::DerPrefixMismatch { expected, actual }
            }
            ic_agent::AgentError::NoRootKeyInStatus(s) => {
                AgentErrorDetail::NoRootKeyInStatus(s.to_string())
            }
            ic_agent::AgentError::WalletCallFailed(s) => AgentErrorDetail::WalletCallFailed(s),
            ic_agent::AgentError::WalletError(s) => AgentErrorDetail::WalletError(s),
            ic_agent::AgentError::WalletUpgradeRequired(s) => {
                AgentErrorDetail::WalletUpgradeRequired(s)
            }
            ic_agent::AgentError::ResponseSizeExceededLimit() => {
                AgentErrorDetail::ResponseSizeExceededLimit
            }
            ic_agent::AgentError::TransportError(e) => {
                AgentErrorDetail::TransportError(e.to_string())
            }
            ic_agent::AgentError::CallDataMismatch {
                field,
                value_arg,
                value_cbor,
            } => AgentErrorDetail::CallDataMismatch {
                field,
                value_arg,
                value_cbor,
            },
            ic_agent::AgentError::InvalidRejectCode(e) => {
                AgentErrorDetail::InvalidRejectCode(e.to_string())
            }
            ic_agent::AgentError::RouteProviderError(s) => AgentErrorDetail::RouteProviderError(s),
            ic_agent::AgentError::InvalidHttpResponse(s) => {
                AgentErrorDetail::InvalidHttpResponse(s)
            }
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
