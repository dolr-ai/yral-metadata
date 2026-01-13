use axum::{
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

use crate::session::YralAuthClaim;
use crate::utils::error::Error as AppError;
use types::*;

struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            )
        }
    }
}

/// Main structure to generate OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    paths(
        crate::api::handlers::set_user_metadata,
        crate::api::handlers::admin_set_user_metadata,
        crate::api::handlers::get_user_metadata,
        crate::api::handlers::delete_metadata_bulk,
        crate::api::handlers::get_user_metadata_bulk,
        crate::api::handlers::get_canister_to_principal_bulk,
        crate::notifications::register_device,
        crate::notifications::unregister_device,
        crate::notifications::send_notification,
        crate::session::update_session_as_registered,
        crate::session::update_session_as_registered_v2
    ),
    components(schemas(
        AppError,
        DeviceRegistrationToken,
        NotificationKey,
        UserMetadata,
        UserMetadataV2,
        SetUserMetadataReqMetadata,
        SetUserMetadataReq,
        BulkUsers,
        BulkGetUserMetadataReq,
        CanisterToPrincipalReq,
        RegisterDeviceReq,
        UnregisterDeviceReq,
        NotificationPayload,
        SendNotificationReq,
        CanisterSessionRegisteredRes,
        YralAuthClaim
    )),
    modifiers(&BearerAuth)
)]
pub(crate) struct ApiDoc;

pub async fn get_swagger(Path(tail): Path<String>) -> Result<Response, AppError> {
    if tail == "swagger.json" {
        let spec = ApiDoc::openapi()
            .to_json()
            .map_err(|err| AppError::SwaggerUi(err.to_string()))?;
        return Ok((StatusCode::OK, [("content-type", "application/json")], spec).into_response());
    }

    let config =
        Arc::new(utoipa_swagger_ui::Config::new(["/explorer/swagger.json"]).use_base_layout());

    match utoipa_swagger_ui::serve(&tail, config.clone())
        .map_err(|err| AppError::SwaggerUi(err.to_string()))?
    {
        None => Err(AppError::SwaggerUi(format!("path not found: {}", tail))),
        Some(file) => Ok((
            StatusCode::OK,
            [("content-type", file.content_type)],
            file.bytes.to_vec(),
        )
            .into_response()),
    }
}

pub async fn get_swagger_root() -> Result<Response, AppError> {
    let config =
        Arc::new(utoipa_swagger_ui::Config::new(["/explorer/swagger.json"]).use_base_layout());

    match utoipa_swagger_ui::serve("index.html", config.clone())
        .map_err(|err| AppError::SwaggerUi(err.to_string()))?
    {
        None => Err(AppError::SwaggerUi("path not found".to_string())),
        Some(file) => Ok((
            StatusCode::OK,
            [("content-type", file.content_type)],
            file.bytes.to_vec(),
        )
            .into_response()),
    }
}
