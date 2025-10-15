use ntex::service::{Middleware, Service, ServiceCtx};
use ntex::web::{Error, ErrorRenderer, WebRequest, WebResponse};
use std::time::Instant;

/// Middleware for capturing HTTP request/response details in Sentry
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

    fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> impl std::future::Future<Output = Result<Self::Response, Self::Error>> {
        async move {
            let start_time = Instant::now();
            let method = req.method().to_string();
            let path = req.path().to_string();
            let query = req.query_string().to_string();

        // Add breadcrumb for incoming request
        sentry::add_breadcrumb(sentry::Breadcrumb {
            ty: "http".into(),
            category: Some("request".into()),
            message: Some(format!("{} {}", method, path)),
            level: sentry::Level::Info,
            data: {
                let mut map = std::collections::BTreeMap::new();
                map.insert("method".to_string(), method.clone().into());
                map.insert("path".to_string(), path.clone().into());
                if !query.is_empty() {
                    map.insert("query".to_string(), query.into());
                }
                map
            },
            ..Default::default()
        });

        // Start a transaction for this request
        let transaction_name = format!("{} {}", method, path);
        let transaction = crate::sentry_utils::start_transaction(&transaction_name, "http.server");

        // Call the next service
        let result = ctx.call(&self.service, req).await;

        let duration = start_time.elapsed();

        match &result {
            Ok(response) => {
                let status = response.status().as_u16();

                // Capture response context
                crate::sentry_utils::capture_response_context(status, duration.as_millis() as u64);

                // Log errors (4xx, 5xx) with appropriate level
                if status >= 400 {
                    let level = if status >= 500 {
                        sentry::Level::Error
                    } else {
                        sentry::Level::Warning
                    };

                    sentry::add_breadcrumb(sentry::Breadcrumb {
                        ty: "http".into(),
                        category: Some("error".into()),
                        message: Some(format!("{} {} returned {}", method, path, status)),
                        level,
                        data: {
                            let mut map = std::collections::BTreeMap::new();
                            map.insert("status".to_string(), status.into());
                            map.insert("duration_ms".to_string(), (duration.as_millis() as u64).into());
                            map
                        },
                        ..Default::default()
                    });
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
                sentry::add_breadcrumb(sentry::Breadcrumb {
                    ty: "error".into(),
                    category: Some("http".into()),
                    message: Some(format!("Request failed: {} {}", method, path)),
                    level: sentry::Level::Error,
                    data: {
                        let mut map = std::collections::BTreeMap::new();
                        map.insert("error".to_string(), format!("{:?}", error).into());
                        map.insert("duration_ms".to_string(), (duration.as_millis() as u64).into());
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
        }
    }
}
