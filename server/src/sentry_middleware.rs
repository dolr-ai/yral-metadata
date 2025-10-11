use ntex::service::{Middleware, Service, ServiceCtx};
use ntex::web::{Error, ErrorRenderer, WebRequest, WebResponse};
use sentry::protocol::{Event, Level};
use std::sync::Arc;
use std::time::Instant;

/// Middleware that integrates Sentry error tracking with ntex
///
/// Features:
/// - Performance monitoring with transaction tracking
/// - Request/response context capture
/// - Automatic error reporting
/// - Request ID tracking
/// - Privacy-aware (filters sensitive headers)
pub struct SentryMiddleware;

impl<S> Middleware<S> for SentryMiddleware {
    type Service = SentryMiddlewareService<S>;

    fn create(&self, service: S) -> Self::Service {
        SentryMiddlewareService { service }
    }
}

pub struct SentryMiddlewareService<S> {
    service: S,
}

impl<S, Err> Service<WebRequest<Err>> for SentryMiddlewareService<S>
where
    S: Service<WebRequest<Err>, Response = WebResponse, Error = Error>,
    Err: ErrorRenderer,
{
    type Response = WebResponse;
    type Error = Error;

    ntex::forward_poll_ready!(service);
    ntex::forward_poll_shutdown!(service);

    async fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        let start_time = Instant::now();

        // Capture request details before moving req
        let method = req.method().to_string();
        let path = req.path().to_string();

        // Create a new Sentry hub for this request
        let hub = sentry::Hub::new_from_top(sentry::Hub::current());

        // Generate or extract request ID
        let request_id = req
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        // Create transaction name from method and path
        let transaction_name = format!("{} {}", method, path);

        // Start a transaction for performance monitoring
        let transaction = sentry::start_transaction(sentry::TransactionContext::new(
            &transaction_name,
            "http.server",
        ));

        // Configure Sentry scope with request information
        hub.configure_scope(|scope| {
            scope.set_transaction(Some(&transaction_name));
            scope.set_tag("request_id", &request_id);

            // Add request details
            scope.set_tag("http.method", &method);
            scope.set_tag("http.url", &path);

            // Add query string if present
            let query = req.query_string();
            if !query.is_empty() {
                scope.set_extra("query_string", query.into());
            }

            // Add headers (excluding sensitive ones)
            for (name, value) in req.headers() {
                let name_str = name.as_str();
                // Skip sensitive headers
                if !name_str.eq_ignore_ascii_case("authorization")
                    && !name_str.eq_ignore_ascii_case("cookie")
                    && !name_str.eq_ignore_ascii_case("x-api-key")
                {
                    if let Ok(value_str) = value.to_str() {
                        scope.set_extra(&format!("header.{}", name_str), value_str.into());
                    }
                }
            }

            // Add client IP if available
            if let Some(peer) = req.peer_addr() {
                scope.set_extra("client_ip", peer.to_string().into());
                scope.set_tag("client_ip", &peer.to_string());
            }
        });

        // Run the request within the Sentry hub context
        let hub_arc = Arc::new(hub);
        let result =
            sentry::Hub::run(hub_arc, || async { ctx.call(&self.service, req).await }).await;

        let duration = start_time.elapsed();

        match result {
            Ok(response) => {
                let status = response.status();

                // Set transaction status and finish
                if status.is_success() {
                    transaction.set_status(sentry::protocol::SpanStatus::Ok);
                } else if status.is_client_error() {
                    transaction.set_status(sentry::protocol::SpanStatus::InvalidArgument);
                } else if status.is_server_error() {
                    transaction.set_status(sentry::protocol::SpanStatus::InternalError);
                }
                transaction.set_tag("http.status_code", &status.as_u16().to_string());
                transaction.finish();

                // Log request duration
                log::debug!(
                    "Request {} {} completed with status {} in {:?}",
                    method,
                    path,
                    status.as_u16(),
                    duration
                );

                // Capture non-2xx status codes as breadcrumbs
                if status.is_client_error() || status.is_server_error() {
                    sentry::add_breadcrumb(sentry::Breadcrumb {
                        ty: "http".into(),
                        level: if status.is_server_error() {
                            Level::Error
                        } else {
                            Level::Warning
                        },
                        message: Some(format!(
                            "HTTP {} response for {} {} ({}ms)",
                            status.as_u16(),
                            method,
                            path,
                            duration.as_millis()
                        )),
                        data: {
                            let mut data = std::collections::BTreeMap::new();
                            data.insert(
                                "duration_ms".to_string(),
                                (duration.as_millis() as u64).into(),
                            );
                            data.insert("status_code".to_string(), status.as_u16().into());
                            data.insert("request_id".to_string(), request_id.clone().into());
                            data
                        },
                        ..Default::default()
                    });

                    // For 5xx errors, capture as Sentry event
                    if status.is_server_error() {
                        sentry::capture_event(Event {
                            message: Some(format!(
                                "HTTP {} error: {} {}",
                                status.as_u16(),
                                method,
                                path
                            )),
                            level: Level::Error,
                            ..Default::default()
                        });
                    }
                }

                Ok(response)
            }
            Err(err) => {
                // Set transaction as error and finish
                transaction.set_status(sentry::protocol::SpanStatus::InternalError);
                transaction.finish();

                // Capture the error in Sentry with full context
                sentry::capture_event(Event {
                    message: Some(format!("Request error: {} {} - {}", method, path, err)),
                    level: Level::Error,
                    ..Default::default()
                });

                log::error!(
                    "Request {} {} failed with error: {} (after {:?})",
                    method,
                    path,
                    err,
                    duration
                );

                Err(err)
            }
        }
    }
}
