use std::sync::Arc;

use ntex::util::Bytes;
use ntex::web;
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
        crate::api::set_user_metadata,
        crate::api::admin_set_user_metadata,
        crate::api::get_user_metadata,
        crate::api::delete_metadata_bulk,
        crate::api::get_user_metadata_bulk,
        crate::api::get_canister_to_principal_bulk,
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

#[web::get("/{tail}*")]
async fn get_swagger(
    tail: web::types::Path<String>,
    openapi_conf: web::types::State<Arc<utoipa_swagger_ui::Config<'static>>>,
) -> Result<web::HttpResponse, AppError> {
    if tail.as_ref() == "swagger.json" {
        let spec = ApiDoc::openapi()
            .to_json()
            .map_err(|err| AppError::SwaggerUi(err.to_string()))?;
        return Ok(web::HttpResponse::Ok()
            .content_type("application/json")
            .body(spec));
    }
    let conf = openapi_conf.as_ref().clone();
    match utoipa_swagger_ui::serve(&tail, conf.into())
        .map_err(|err| AppError::SwaggerUi(err.to_string()))?
    {
        None => Err(AppError::SwaggerUi(format!("path not found: {}", tail))),
        Some(file) => Ok({
            let bytes = Bytes::from(file.bytes.to_vec());
            web::HttpResponse::Ok()
                .content_type(file.content_type)
                .body(bytes)
        }),
    }
}

pub fn ntex_config(config: &mut web::ServiceConfig) {
    let swagger_config =
        Arc::new(utoipa_swagger_ui::Config::new(["/explorer/swagger.json"]).use_base_layout());
    config.service(
        web::scope("/explorer/")
            .state(swagger_config)
            .service(get_swagger),
    );
}
