use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
    response::IntoResponse
};
use candid::Principal;
use std::sync::Arc;
use types::{
    ApiResult, BulkGetUserMetadataReq, BulkGetUserMetadataRes, BulkUsers, CanisterToPrincipalReq,
    CanisterToPrincipalRes, DeleteMetadataBulkRes, GetUserMetadataV2Res, SetUserMetadataReq,
    SetUserMetadataRes,
};

use crate::{
    api::implementation::{
        delete_metadata_bulk_impl, get_canister_to_principal_bulk_impl,
        get_user_metadata_bulk_impl, get_user_metadata_impl, set_user_metadata_impl,
        set_user_metadata_using_admin_identity_impl,
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
pub async fn set_user_metadata(
    State(state): State<Arc<AppState>>,
    Path(user_principal): Path<Principal>,
    Json(req): Json<SetUserMetadataReq>,
) -> Result<Json<ApiResult<SetUserMetadataRes>>> {
    let principal = user_principal;

    // Add user context to Sentry
    // crate::sentry_utils::add_user_context(principal, None);
    // crate::sentry_utils::add_operation_breadcrumb(
    //     "metadata",
    //     &format!("Setting metadata for user: {}", principal),
    //     sentry::Level::Info,
    // );

    let result = set_user_metadata_impl(&state.redis, principal, req, CANISTER_TO_PRINCIPAL_KEY)
        .await
        .map_err(|e| {
            // crate::sentry_utils::capture_api_error(
            //     &e,
            //     "/metadata/{user_principal}",
            //     Some(&principal.to_text()),
            // );
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
pub async fn admin_set_user_metadata(
    State(state): State<Arc<AppState>>,
    Path(user_principal): Path<Principal>,
    Json(req): Json<SetUserMetadataReq>,
) -> Result<Json<ApiResult<SetUserMetadataRes>>> {
    let admin_principal = state.backend_admin_ic_agent.get_principal().map_err(|e| {
        log::error!("Error getting admin identity principal: {}", e);
        Error::EnvironmentVariable(std::env::VarError::NotPresent)
    })?;

    let result = set_user_metadata_using_admin_identity_impl(
        &state.redis,
        admin_principal,
        user_principal,
        req,
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
pub async fn get_user_metadata(
    State(state): State<Arc<AppState>>,
    Path(identifier): Path<String>,
) -> Result<Json<ApiResult<GetUserMetadataV2Res>>> {
    // crate::sentry_utils::add_operation_breadcrumb(
    //     "metadata",
    //     &format!("Getting metadata for: {}", identifier),
    //     sentry::Level::Info,
    // );

    let result = get_user_metadata_impl(&state.redis, identifier.clone())
        .await
        .map_err(|e| {
            // crate::sentry_utils::capture_api_error(
            //     &e,
            //     "/metadata/{username_or_principal}",
            //     Some(&identifier),
            // );
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
pub async fn delete_metadata_bulk(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BulkUsers>,
) -> Result<Json<ApiResult<DeleteMetadataBulkRes>>> {
    let token = headers
        .get("Authorization")
        .ok_or(Error::AuthTokenMissing)?
        .to_str()
        .map_err(|_| Error::AuthTokenInvalid)?;
    let token = token.trim_start_matches("Bearer ");

    // Verify JWT token
    crate::auth::verify_token(token, &state.jwt_details)?;

    delete_metadata_bulk_impl(&state.redis, &req, CANISTER_TO_PRINCIPAL_KEY).await?;
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
pub async fn get_user_metadata_bulk(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BulkGetUserMetadataReq>,
) -> Result<Json<ApiResult<BulkGetUserMetadataRes>>> {
    let user_count = req.users.len();

    // crate::sentry_utils::add_operation_breadcrumb(
    //     "metadata",
    //     &format!("Bulk fetch metadata for {} users", user_count),
    //     sentry::Level::Info,
    // );

    let result = get_user_metadata_bulk_impl(&state.redis, req)
        .await
        .map_err(|e| {
            log::error!("Error fetching bulk user metadata: {}", e);
            // crate::sentry_utils::capture_api_error(&e, "/metadata-bulk", None);
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
pub async fn get_canister_to_principal_bulk(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CanisterToPrincipalReq>,
) -> Result<Json<ApiResult<CanisterToPrincipalRes>>> {
    let result =
        get_canister_to_principal_bulk_impl(&state.redis, req, CANISTER_TO_PRINCIPAL_KEY).await?;
    Ok(Json(Ok(result)))
}

/// Health check endpoint
pub async fn healthz() -> axum::response::Response {
    Json(serde_json::json!({"status": "ok"})).into_response()
}