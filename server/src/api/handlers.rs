use candid::Principal;
use ntex::web::{
    self,
    types::{Json, Path, State},
};
use types::{
    ApiResult, BulkGetUserMetadataReq, BulkGetUserMetadataRes, BulkUsers, CanisterToPrincipalReq,
    CanisterToPrincipalRes, GetUserMetadataV2Res, SetUserMetadataReq, SetUserMetadataRes,
};

use crate::{
    api::implementation::{
        delete_metadata_bulk_impl, get_canister_to_principal_bulk_impl,
        get_user_metadata_bulk_impl, get_user_metadata_impl, set_user_metadata_impl, set_user_metadata_using_admin_identity_impl,
    },
    services::error_wrappers::{ErrorWrapper, NullOk, OkWrapper},
    state::AppState,
    utils::{
        canister::CANISTER_TO_PRINCIPAL_KEY,
        error::{Error, Result},
    },
};

#[utoipa::path(
    post,
    path = "/metadata/{user_principal}",
    params(
        ("user_principal" = String, Path, description = "User principal ID")
    ),
    request_body = SetUserMetadataReq,
    responses(
        (status = 200, description = "Set user metadata successfully", body = OkWrapper<SetUserMetadataRes>),
        (status = 400, description = "Invalid request", body = ErrorWrapper<SetUserMetadataRes>),
        (status = 401, description = "Unauthorized", body = ErrorWrapper<SetUserMetadataRes>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<SetUserMetadataRes>)
    )
)]
#[web::post("/metadata/{user_principal}")]
async fn set_user_metadata(
    state: State<AppState>,
    user_principal: Path<Principal>,
    req: Json<SetUserMetadataReq>,
) -> Result<Json<ApiResult<SetUserMetadataRes>>> {
    let principal = *user_principal;

    // Add user context to Sentry
    crate::sentry_utils::add_user_context(principal, None);
    crate::sentry_utils::add_operation_breadcrumb(
        "metadata",
        &format!("Setting metadata for user: {}", principal),
        sentry::Level::Info,
    );

    let result = set_user_metadata_impl(
        &state.redis,
        principal,
        req.0,
        CANISTER_TO_PRINCIPAL_KEY,
    )
    .await
    .map_err(|e| {
        crate::sentry_utils::capture_api_error(&e, "/metadata/{user_principal}", Some(&principal.to_text()));
        e
    })?;

    Ok(Json(Ok(result)))
}


#[utoipa::path(
    post,
    path = "/metadata/{user_principal}",
    params(
        ("user_principal" = String, Path, description = "User principal ID")
    ),
    request_body = SetUserMetadataReq,
    responses(
        (status = 200, description = "Set user metadata successfully", body = OkWrapper<SetUserMetadataRes>),
        (status = 400, description = "Invalid request", body = ErrorWrapper<SetUserMetadataRes>),
        (status = 401, description = "Unauthorized", body = ErrorWrapper<SetUserMetadataRes>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<SetUserMetadataRes>)
    )
)]
#[web::post("/admin/metadata/{user_principal}")]
async fn admin_set_user_metadata(
    state: State<AppState>,
    user_principal: Path<Principal>,
    req: Json<SetUserMetadataReq>,
) -> Result<Json<ApiResult<SetUserMetadataRes>>> {

    let admin_principal = state.backend_admin_ic_agent.get_principal().map_err(|e| {
        log::error!("Error getting admin identity principal: {}", e);
        Error::EnvironmentVariable(std::env::VarError::NotPresent)
    })?;

    let result = set_user_metadata_using_admin_identity_impl(
        &state.redis,
        admin_principal,
        *user_principal,
        req.0,
        CANISTER_TO_PRINCIPAL_KEY,
    )
    .await?;
    Ok(Json(Ok(result)))
}


#[utoipa::path(
    get,
    path = "/metadata/{user_principal}",
    params(
        ("username_or_principal" = String, Path, description = "Username or principal ID")
    ),
    responses(
        (status = 200, description = "Get user metadata successfully", body = OkWrapper<GetUserMetadataV2Res>),
        (status = 404, description = "User metadata not found", body = ErrorWrapper<GetUserMetadataV2Res>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<GetUserMetadataV2Res>)
    )
)]
#[web::get("/metadata/{username_or_principal}")]
async fn get_user_metadata(
    state: State<AppState>,
    path: Path<String>,
) -> Result<Json<ApiResult<GetUserMetadataV2Res>>> {
    let identifier = path.into_inner();

    crate::sentry_utils::add_operation_breadcrumb(
        "metadata",
        &format!("Getting metadata for: {}", identifier),
        sentry::Level::Info,
    );

    let result = get_user_metadata_impl(&state.redis, identifier.clone()).await
        .map_err(|e| {
            crate::sentry_utils::capture_api_error(&e, "/metadata/{username_or_principal}", Some(&identifier));
            e
        })?;

    Ok(Json(Ok(result)))
}

#[utoipa::path(
    delete,
    path = "/metadata/bulk",
    request_body = BulkUsers,
    responses(
        (status = 200, description = "Delete user metadata in bulk successfully", body = NullOk), // OkWrapper<()> panics for some reason
        (status = 400, description = "Invalid request", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 401, description = "Unauthorized", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<crate::utils::error::Error>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[web::delete("/metadata/bulk")]
async fn delete_metadata_bulk(
    state: State<AppState>,
    req: Json<BulkUsers>,
    http_req: web::HttpRequest,
) -> Result<Json<ApiResult<()>>> {
    let token = http_req
        .headers()
        .get("Authorization")
        .ok_or(Error::AuthTokenMissing)?
        .to_str()
        .map_err(|_| Error::AuthTokenInvalid)?;
    let token = token.trim_start_matches("Bearer ");

    // Verify JWT token
    crate::auth::verify_token(token, &state.jwt_details)?;

    delete_metadata_bulk_impl(&state.redis, req.0, CANISTER_TO_PRINCIPAL_KEY).await?;
    Ok(Json(Ok(())))
}

#[utoipa::path(
    post,
    path = "/metadata-bulk",
    request_body = BulkGetUserMetadataReq,
    responses(
        (status = 200, description = "Get user metadata in bulk successfully", body = String, content_type = "application/json"),
        (status = 500, description = "Internal server error", body = ErrorWrapper<String>)
    )
)]
#[web::post("/metadata-bulk")]
async fn get_user_metadata_bulk(
    state: State<AppState>,
    req: Json<BulkGetUserMetadataReq>,
) -> Result<Json<ApiResult<BulkGetUserMetadataRes>>> {
    let user_count = req.0.users.len();

    crate::sentry_utils::add_operation_breadcrumb(
        "metadata",
        &format!("Bulk fetch metadata for {} users", user_count),
        sentry::Level::Info,
    );

    let result = get_user_metadata_bulk_impl(&state.redis, req.0)
        .await
        .map_err(|e| {
            log::error!("Error fetching bulk user metadata: {}", e);
            crate::sentry_utils::capture_api_error(&e, "/metadata-bulk", None);
            e
        })?;
    Ok(Json(Ok(result)))
}

#[utoipa::path(
    post,
    path = "/canister-to-principal/bulk",
    request_body = CanisterToPrincipalReq,
    responses(
        (status = 200, description = "Get canister to principal mapping in bulk successfully", body = OkWrapper<CanisterToPrincipalRes>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<CanisterToPrincipalRes>)
    )
)]
#[web::post("/canister-to-principal/bulk")]
async fn get_canister_to_principal_bulk(
    state: State<AppState>,
    req: Json<CanisterToPrincipalReq>,
) -> Result<Json<ApiResult<CanisterToPrincipalRes>>> {
    let result =
        get_canister_to_principal_bulk_impl(&state.redis, req.0, CANISTER_TO_PRINCIPAL_KEY).await?;
    Ok(Json(Ok(result)))
}
