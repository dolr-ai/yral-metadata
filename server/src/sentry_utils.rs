use candid::Principal;
use ntex::web::HttpRequest;
use sentry::Level;
use sentry::protocol::Uuid;
use std::collections::BTreeMap;

/// Captures HTTP request context and adds it to the current Sentry scope
pub fn capture_request_context(req: &HttpRequest, user_principal: Option<Principal>) {
    sentry::configure_scope(|scope| {
        // Add request details
        scope.set_tag("http.method", req.method().as_str());
        scope.set_tag("http.path", req.path());

        // Add user context if available
        if let Some(principal) = user_principal {
            scope.set_user(Some(sentry::User {
                id: Some(principal.to_text()),
                ..Default::default()
            }));
        }

        // Add request headers (sanitized - exclude Authorization)
        let mut headers_map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        for (name, value) in req.headers() {
            let name_str = name.as_str();
            if name_str.to_lowercase() != "authorization" {
                if let Ok(value_str) = value.to_str() {
                    headers_map.insert(name_str.to_string(), serde_json::Value::String(value_str.to_string()));
                }
            }
        }
        scope.set_context("headers", sentry::protocol::Context::Other(headers_map));

        // Add query parameters
        if !req.query_string().is_empty() {
            scope.set_extra("query_string", req.query_string().to_string().into());
        }

        // Add connection info
        if let Some(peer_addr) = req.peer_addr() {
            scope.set_tag("client.ip", peer_addr.to_string());
        }

        // Add user agent
        if let Some(user_agent) = req.headers().get("user-agent") {
            if let Ok(ua_str) = user_agent.to_str() {
                scope.set_tag("http.user_agent", ua_str);
            }
        }
    });
}

/// Captures response context (status code, timing)
pub fn capture_response_context(status_code: u16, duration_ms: u64) {
    sentry::configure_scope(|scope| {
        scope.set_tag("http.status_code", status_code.to_string());
        scope.set_extra("response.duration_ms", duration_ms.into());

        // Add breadcrumb for response
        sentry::add_breadcrumb(sentry::Breadcrumb {
            ty: "http".into(),
            category: Some("response".into()),
            message: Some(format!("HTTP Response: {} ({}ms)", status_code, duration_ms)),
            level: if status_code >= 500 {
                Level::Error
            } else if status_code >= 400 {
                Level::Warning
            } else {
                Level::Info
            },
            ..Default::default()
        });
    });
}

/// Adds user context to Sentry scope
pub fn add_user_context(user_principal: Principal, username: Option<&str>) {
    sentry::configure_scope(|scope| {
        scope.set_user(Some(sentry::User {
            id: Some(user_principal.to_text()),
            username: username.map(|s| s.to_string()),
            ..Default::default()
        }));
    });
}

/// Adds a breadcrumb for tracking important operations
pub fn add_operation_breadcrumb(category: &str, message: &str, level: Level) {
    sentry::add_breadcrumb(sentry::Breadcrumb {
        ty: "default".into(),
        category: Some(category.into()),
        message: Some(message.into()),
        level,
        ..Default::default()
    });
}

/// Captures an error with additional context
pub fn capture_error_with_context(
    error: &dyn std::error::Error,
    context: BTreeMap<String, String>,
) -> Uuid {
    sentry::with_scope(
        |scope| {
            for (key, value) in context {
                scope.set_extra(&key, value.into());
            }
        },
        || sentry::capture_error(error),
    )
}

/// Starts a Sentry transaction for performance monitoring
pub fn start_transaction(name: &str, operation: &str) -> sentry::TransactionOrSpan {
    let ctx = sentry::TransactionContext::new(name, operation);
    sentry::TransactionOrSpan::Transaction(sentry::start_transaction(ctx))
}

/// Adds breadcrumb for Redis operations
pub fn add_redis_breadcrumb(operation: &str, key: &str, success: bool) {
    sentry::add_breadcrumb(sentry::Breadcrumb {
        ty: "query".into(),
        category: Some("redis".into()),
        message: Some(format!("Redis {}: {}", operation, key)),
        level: if success { Level::Debug } else { Level::Error },
        data: {
            let mut map = BTreeMap::new();
            map.insert("operation".to_string(), operation.into());
            map.insert("key".to_string(), key.into());
            map.insert("success".to_string(), success.into());
            map
        },
        ..Default::default()
    });
}

/// Adds breadcrumb for Firebase operations
pub fn add_firebase_breadcrumb(operation: &str, user_principal: &str, success: bool) {
    sentry::add_breadcrumb(sentry::Breadcrumb {
        ty: "http".into(),
        category: Some("firebase".into()),
        message: Some(format!("Firebase {}: {}", operation, user_principal)),
        level: if success { Level::Info } else { Level::Error },
        data: {
            let mut map = BTreeMap::new();
            map.insert("operation".to_string(), operation.into());
            map.insert("user".to_string(), user_principal.into());
            map.insert("success".to_string(), success.into());
            map
        },
        ..Default::default()
    });
}

/// Adds breadcrumb for IC canister calls
pub fn add_canister_call_breadcrumb(
    canister_id: &str,
    method: &str,
    success: bool,
) {
    sentry::add_breadcrumb(sentry::Breadcrumb {
        ty: "rpc".into(),
        category: Some("canister".into()),
        message: Some(format!("Canister call: {}::{}", canister_id, method)),
        level: if success { Level::Info } else { Level::Error },
        data: {
            let mut map = BTreeMap::new();
            map.insert("canister_id".to_string(), canister_id.into());
            map.insert("method".to_string(), method.into());
            map.insert("success".to_string(), success.into());
            map
        },
        ..Default::default()
    });
}

/// Captures API error with full context
pub fn capture_api_error(
    error: &crate::utils::error::Error,
    endpoint: &str,
    user_principal: Option<&str>,
) -> Uuid {
    sentry::with_scope(
        |scope| {
            scope.set_tag("endpoint", endpoint);
            if let Some(principal) = user_principal {
                scope.set_tag("user_principal", principal);
            }
            scope.set_level(Some(match error {
                crate::utils::error::Error::AuthTokenMissing
                | crate::utils::error::Error::AuthTokenInvalid
                | crate::utils::error::Error::Jwt(_) => Level::Warning,
                crate::utils::error::Error::Redis(_)
                | crate::utils::error::Error::Bb8(_)
                | crate::utils::error::Error::Agent(_) => Level::Error,
                _ => Level::Info,
            }));
        },
        || {
            sentry::capture_message(
                &format!("API Error at {}: {}", endpoint, error),
                Level::Error,
            )
        },
    )
}
