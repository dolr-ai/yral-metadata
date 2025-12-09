use axum::{body::Bytes, extract::Request, response::Response};
use sentry::Hub;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tower::{Layer, Service};

/// Global request counter for generating unique request IDs
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Maximum body size to capture (default 10KB)
#[allow(dead_code)]
fn get_body_limit() -> usize {
    env::var("SENTRY_HTTP_BODY_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10240)
}

/// Check if HTTP logging is enabled
fn is_http_logging_enabled() -> bool {
    env::var("SENTRY_ENABLE_HTTP_LOGGING")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(true)
}

/// Middleware for capturing HTTP request/response details in Sentry
#[derive(Clone)]
pub struct SentryMiddleware;

impl<S> Layer<S> for SentryMiddleware {
    type Service = SentryMiddlewareService<S>;

    fn layer(&self, service: S) -> Self::Service {
        SentryMiddlewareService { service }
    }
}

#[derive(Clone)]
pub struct SentryMiddlewareService<S> {
    service: S,
}

/// Check if a body contains sensitive field names
#[allow(dead_code)]
fn contains_sensitive_field(text: &str) -> bool {
    let text_lower = text.to_lowercase();
    const SENSITIVE_FIELDS: &[&str] = &[
        "signature",
        "registration_token",
        "notification_key",
        "authorization",
        "bearer",
        "token",
        "api_key",
        "secret",
        "password",
    ];
    SENSITIVE_FIELDS
        .iter()
        .any(|field| text_lower.contains(field))
}

/// Parse bytes and scrub sensitive data (only called on errors)
#[allow(dead_code)]
fn parse_and_scrub_bytes(bytes: &Bytes) -> Option<String> {
    let body_str = String::from_utf8_lossy(bytes);

    // Quick check - if no sensitive fields, return as-is
    if !contains_sensitive_field(&body_str) {
        return Some(body_str.to_string());
    }

    // Scrub the body using the scrubbing module
    Some(crate::middleware::sentry_scrub::scrub_body(&body_str))
}

/// Add lightweight breadcrumb for successful requests (no body parsing)
fn add_lightweight_breadcrumb(
    request_id: u64,
    method: &str,
    path: &str,
    status: u16,
    duration_ms: u64,
) {
    Hub::current().add_breadcrumb(sentry::Breadcrumb {
        ty: "http".into(),
        category: Some("http.response".into()),
        message: Some(format!(
            "[req_id:{}] {} {} {} ({}ms)",
            request_id, method, path, status, duration_ms
        )),
        level: sentry::Level::Info,
        data: {
            let mut map = std::collections::BTreeMap::new();
            map.insert("request_id".to_string(), request_id.into());
            map.insert("method".to_string(), method.into());
            map.insert("url".to_string(), path.into());
            map.insert("status_code".to_string(), status.into());
            map.insert("duration_ms".to_string(), duration_ms.into());
            map
        },
        ..Default::default()
    });
}

/// Add detailed request breadcrumb with body (only for errors)
fn add_request_breadcrumb(
    request_id: u64,
    method: &str,
    path: &str,
    query: &str,
    body: Option<String>,
) {
    Hub::current().add_breadcrumb(sentry::Breadcrumb {
        ty: "http".into(),
        category: Some("http.request".into()),
        message: Some(format!("[req_id:{}] {} {}", request_id, method, path)),
        level: sentry::Level::Info,
        data: {
            let mut map = std::collections::BTreeMap::new();
            map.insert("request_id".to_string(), request_id.into());
            map.insert("method".to_string(), method.into());
            map.insert("url".to_string(), path.into());
            if !query.is_empty() {
                map.insert("query".to_string(), query.into());
            }
            if let Some(b) = body {
                map.insert("body".to_string(), b.into());
            }
            map
        },
        ..Default::default()
    });
}

/// Add detailed response breadcrumb with body (only for errors)
fn add_response_breadcrumb(request_id: u64, status: u16, duration_ms: u64, body: Option<String>) {
    let level = if status >= 500 {
        sentry::Level::Error
    } else {
        sentry::Level::Warning
    };

    Hub::current().add_breadcrumb(sentry::Breadcrumb {
        ty: "http".into(),
        category: Some("http.response".into()),
        message: Some(format!(
            "[req_id:{}] {} ({}ms)",
            request_id, status, duration_ms
        )),
        level,
        data: {
            let mut map = std::collections::BTreeMap::new();
            map.insert("request_id".to_string(), request_id.into());
            map.insert("status_code".to_string(), status.into());
            map.insert("duration_ms".to_string(), duration_ms.into());
            if let Some(b) = body {
                map.insert("body".to_string(), b.into());
            }
            map
        },
        ..Default::default()
    });
}

impl<S> Service<Request> for SentryMiddlewareService<S>
where
    S: Service<Request, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Debug + Copy,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let mut inner = self.service.clone();

        Box::pin(async move {
            if !is_http_logging_enabled() {
                // Logging disabled - just pass through
                return inner.call(req).await;
            }
            // Generate unique request ID
            let request_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);

            // Create isolated Sentry Hub for this request
            // Note: Hub isolation in async contexts is tricky. We use configure_scope
            // to add request-specific data, but breadcrumbs will use Hub::current()
            // which should be bound to this request's context
            Hub::with_active(|hub| {
                hub.configure_scope(|scope| {
                    scope.set_tag("request_id", request_id.to_string());
                });
            });

            let start_time = Instant::now();
            let method = req.method().to_string();
            let path = req.uri().path().to_string();
            let query = req.uri().query().map(|q| q.to_string()).unwrap_or_default();

            // Start a transaction for this request
            let transaction_name = format!("{} {}", method, path);
            let transaction =
                crate::sentry_utils::start_transaction(&transaction_name, "http.server");

            let result = inner.call(req).await;

            let duration = start_time.elapsed();
            let duration_ms = duration.as_millis() as u64;
            match &result {
                Ok(response) => {
                    let status = response.status().as_u16();

                    // Capture response context
                    crate::sentry_utils::capture_response_context(status, duration_ms);

                    if status >= 400 {
                        // Error response - add detailed breadcrumbs and log
                        log::error!(
                            "[req_id:{}] HTTP Error: {} {} -> {} ({}ms)",
                            request_id,
                            method,
                            path,
                            status,
                            duration_ms
                        );

                        // Note: We don't have access to request/response bodies in ntex without buffering
                        // This is a limitation of the ntex Service trait
                        add_request_breadcrumb(request_id, &method, &path, &query, None);
                        add_response_breadcrumb(request_id, status, duration_ms, None);
                    } else {
                        // Success - add lightweight breadcrumb
                        add_lightweight_breadcrumb(request_id, &method, &path, status, duration_ms);
                    }

                    // Set transaction status
                    transaction.set_status(if status >= 500 {
                        sentry::protocol::SpanStatus::InternalError
                    } else if status >= 400 {
                        sentry::protocol::SpanStatus::InvalidArgument
                    } else {
                        sentry::protocol::SpanStatus::Ok
                    });
                }
                Err(error) => {
                    // Capture error details
                    log::error!(
                        "[req_id:{}] HTTP Error: {} {} -> middleware error ({}ms)",
                        request_id,
                        method,
                        path,
                        duration_ms
                    );

                    Hub::current().add_breadcrumb(sentry::Breadcrumb {
                        ty: "error".into(),
                        category: Some("http".into()),
                        message: Some(format!(
                            "[req_id:{}] Request failed: {} {}",
                            request_id, method, path
                        )),
                        level: sentry::Level::Error,
                        data: {
                            let mut map = std::collections::BTreeMap::new();
                            map.insert("request_id".to_string(), request_id.into());
                            map.insert("error".to_string(), format!("{:?}", error).into());
                            map.insert("duration_ms".to_string(), duration_ms.into());
                            map
                        },
                        ..Default::default()
                    });

                    transaction.set_status(sentry::protocol::SpanStatus::InternalError);
                }
            }

            // Finish the transaction
            transaction.finish();

            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_sensitive_field() {
        assert!(contains_sensitive_field("signature"));
        assert!(contains_sensitive_field("{\"signature\":\"abc\"}"));
        assert!(contains_sensitive_field("Authorization: Bearer xyz"));
        assert!(contains_sensitive_field("registration_token"));
        assert!(!contains_sensitive_field("user_name"));
        assert!(!contains_sensitive_field("user_principal"));
    }

    #[test]
    fn test_scrub_json_body() {
        let body = r#"{"user_name":"alice","signature":"secret123"}"#;
        let bytes = Bytes::from(body);
        let scrubbed = parse_and_scrub_bytes(&bytes);
        assert!(scrubbed.is_some());
        let scrubbed_str = scrubbed.unwrap();
        assert!(scrubbed_str.contains("alice"));
        assert!(scrubbed_str.contains("[REDACTED]"));
        assert!(!scrubbed_str.contains("secret123"));
    }

    #[test]
    fn test_scrub_nested_json() {
        let body = r#"{"user":{"name":"alice","token":"secret"}}"#;
        let bytes = Bytes::from(body);
        let scrubbed = parse_and_scrub_bytes(&bytes);
        assert!(scrubbed.is_some());
        let scrubbed_str = scrubbed.unwrap();
        assert!(scrubbed_str.contains("alice"));
        assert!(scrubbed_str.contains("[REDACTED]"));
        assert!(!scrubbed_str.contains("secret"));
    }

    #[test]
    fn test_scrub_array_json() {
        let body =
            r#"{"items":[{"name":"alice","api_key":"key1"},{"name":"bob","api_key":"key2"}]}"#;
        let bytes = Bytes::from(body);
        let scrubbed = parse_and_scrub_bytes(&bytes);
        assert!(scrubbed.is_some());
        let scrubbed_str = scrubbed.unwrap();
        assert!(scrubbed_str.contains("alice"));
        assert!(scrubbed_str.contains("bob"));
        assert!(scrubbed_str.contains("[REDACTED]"));
        assert!(!scrubbed_str.contains("key1"));
        assert!(!scrubbed_str.contains("key2"));
    }

    #[test]
    fn test_non_sensitive_body() {
        let body = r#"{"user_name":"alice","user_principal":"abc-def"}"#;
        let bytes = Bytes::from(body);
        let scrubbed = parse_and_scrub_bytes(&bytes);
        assert!(scrubbed.is_some());
        let scrubbed_str = scrubbed.unwrap();
        assert_eq!(scrubbed_str, body);
    }
}
