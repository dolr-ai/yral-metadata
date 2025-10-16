use sentry::protocol::{Breadcrumb, Context, Event, Request};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Sensitive field names that should be redacted from Sentry events
const SENSITIVE_FIELDS: &[&str] = &[
    // Authentication & Authorization
    "authorization",
    "bearer",
    "token",
    "jwt",
    "auth_token",
    "access_token",
    "refresh_token",
    "session_token",
    "api_key",
    "secret",
    "password",
    "private_key",
    // yral-metadata specific sensitive fields
    "signature",              // User identity signatures from SetUserMetadataReq
    "registration_token",     // FCM device registration tokens
    "notification_key",       // Firebase notification group keys
    "key",                    // NotificationKey.key field
    // Environment secrets
    "yral_metadata_user_notification_api_key",
];

/// Check if a string contains any sensitive field names
fn contains_sensitive_field(text: &str) -> bool {
    let text_lower = text.to_lowercase();
    SENSITIVE_FIELDS.iter().any(|field| {
        text_lower.contains(field)
    })
}

/// Recursively scrub sensitive data from a JSON value
#[allow(dead_code)]
fn scrub_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            // Scrub all values in the object
            for (key, val) in map.iter_mut() {
                if SENSITIVE_FIELDS.iter().any(|f| key.to_lowercase().contains(f)) {
                    *val = serde_json::Value::String("[REDACTED]".to_string());
                } else {
                    scrub_json_value(val);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            // Scrub all values in the array
            for item in arr.iter_mut() {
                scrub_json_value(item);
            }
        }
        _ => {}
    }
}

/// Scrub sensitive data from a request body string
#[allow(dead_code)]
pub fn scrub_body(body: &str) -> String {
    // Quick check if body contains any sensitive fields
    if !contains_sensitive_field(body) {
        return body.to_string();
    }

    // Try to parse as JSON and scrub
    if let Ok(mut json_value) = serde_json::from_str::<serde_json::Value>(body) {
        scrub_json_value(&mut json_value);
        serde_json::to_string(&json_value).unwrap_or_else(|_| body.to_string())
    } else {
        // For non-JSON bodies, we could use regex scrubbing in the future
        // For now, just return the body as-is if it doesn't parse as JSON
        body.to_string()
    }
}

/// Scrub sensitive data from a Sentry Request
fn scrub_request(request: &mut Request) {
    // Remove sensitive headers
    for sensitive_header in SENSITIVE_FIELDS {
        request.headers.remove(*sensitive_header);
        // Also try capitalized versions
        let capitalized = sensitive_header
            .split('_')
            .map(|s| {
                let mut chars = s.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            })
            .collect::<Vec<_>>()
            .join("-");
        request.headers.remove(&capitalized);
    }

    // Scrub query string if present
    if let Some(query) = &request.query_string {
        if contains_sensitive_field(query) {
            request.query_string = Some("[REDACTED - contains sensitive data]".to_string());
        }
    }

    // Scrub request data/body
    if let Some(data) = &request.data {
        if contains_sensitive_field(&data.to_string()) {
            request.data = Some("[REDACTED - contains sensitive data]".to_string());
        }
    }
}

/// Scrub sensitive data from breadcrumbs
fn scrub_breadcrumbs(breadcrumbs: &mut [Breadcrumb]) {
    for breadcrumb in breadcrumbs.iter_mut() {
        // Scrub message
        if let Some(message) = &breadcrumb.message {
            if contains_sensitive_field(message) {
                breadcrumb.message = Some("[REDACTED - contains sensitive data]".to_string());
            }
        }

        // Scrub data fields
        for (key, value) in breadcrumb.data.iter_mut() {
            if SENSITIVE_FIELDS.iter().any(|f| key.to_lowercase().contains(f)) {
                *value = serde_json::Value::String("[REDACTED]".to_string());
            } else if let serde_json::Value::String(s) = value {
                if contains_sensitive_field(s) {
                    *value = serde_json::Value::String("[REDACTED - contains sensitive data]".to_string());
                }
            }
        }
    }
}

/// Scrub sensitive data from contexts
fn scrub_contexts(contexts: &mut BTreeMap<String, Context>) {
    for (_key, context) in contexts.iter_mut() {
        if let Context::Other(map) = context {
            for (field_key, value) in map.iter_mut() {
                if SENSITIVE_FIELDS.iter().any(|f| field_key.to_lowercase().contains(f)) {
                    *value = serde_json::Value::String("[REDACTED]".to_string());
                } else if let serde_json::Value::String(s) = value {
                    if contains_sensitive_field(s) {
                        *value = serde_json::Value::String("[REDACTED - contains sensitive data]".to_string());
                    }
                }
            }
        }
    }
}

/// Main scrubbing function to be used in Sentry's before_send hook
pub fn scrub_sensitive_data(mut event: Event<'static>) -> Option<Event<'static>> {
    // Scrub request data
    if let Some(request) = &mut event.request {
        scrub_request(request);
    }

    // Scrub breadcrumbs
    if !event.breadcrumbs.is_empty() {
        scrub_breadcrumbs(&mut event.breadcrumbs);
    }

    // Scrub contexts
    scrub_contexts(&mut event.contexts);

    // Scrub extra data
    for (key, value) in event.extra.iter_mut() {
        if SENSITIVE_FIELDS.iter().any(|f| key.to_lowercase().contains(f)) {
            *value = serde_json::Value::String("[REDACTED]".to_string());
        }
    }

    Some(event)
}

/// Create the before_send hook for Sentry initialization
pub fn create_before_send() -> Arc<dyn Fn(Event<'static>) -> Option<Event<'static>> + Send + Sync> {
    Arc::new(scrub_sensitive_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_sensitive_field() {
        assert!(contains_sensitive_field("authorization: Bearer xyz"));
        assert!(contains_sensitive_field("{\"signature\":\"abc123\"}"));
        assert!(contains_sensitive_field("registration_token"));
        assert!(contains_sensitive_field("notification_key"));
        assert!(!contains_sensitive_field("{\"user_name\":\"alice\"}"));
        assert!(!contains_sensitive_field("user_principal"));
    }

    #[test]
    fn test_scrub_json_body() {
        let body = r#"{"user_name":"alice","signature":"secret123","user_principal":"abc"}"#;
        let scrubbed = scrub_body(body);
        assert!(scrubbed.contains("alice"));
        assert!(scrubbed.contains("[REDACTED]"));
        assert!(!scrubbed.contains("secret123"));
    }

    #[test]
    fn test_scrub_nested_json() {
        let body = r#"{"user":{"name":"alice","signature":"secret"},"data":"public"}"#;
        let scrubbed = scrub_body(body);
        assert!(scrubbed.contains("alice"));
        assert!(scrubbed.contains("public"));
        assert!(scrubbed.contains("[REDACTED]"));
        assert!(!scrubbed.contains("secret"));
    }

    #[test]
    fn test_scrub_array_json() {
        let body = r#"{"tokens":[{"token":"abc","user":"alice"},{"token":"xyz","user":"bob"}]}"#;
        let scrubbed = scrub_body(body);
        assert!(scrubbed.contains("alice"));
        assert!(scrubbed.contains("bob"));
        assert!(scrubbed.contains("[REDACTED]"));
        assert!(!scrubbed.contains("abc"));
        assert!(!scrubbed.contains("xyz"));
    }

    #[test]
    fn test_scrub_non_json_body() {
        let body = "plain text without sensitive data";
        let scrubbed = scrub_body(body);
        assert_eq!(scrubbed, body);
    }
}
