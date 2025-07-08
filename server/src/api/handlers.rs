use candid::Principal;
use ntex::web::{
    self,
    types::{Json, Path, State},
};
use types::{
    ApiResult, BulkGetUserMetadataReq, BulkGetUserMetadataRes, BulkUsers, CanisterToPrincipalReq,
    CanisterToPrincipalRes, GetUserMetadataRes, SetUserMetadataReq, SetUserMetadataRes,
};

use crate::{
    api::implementation::{
        delete_metadata_bulk_impl, get_canister_to_principal_bulk_impl,
        get_user_metadata_bulk_impl, get_user_metadata_impl, set_user_metadata_impl,
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
    let result = set_user_metadata_impl(
        &state.redis,
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
        ("user_principal" = String, Path, description = "User principal ID")
    ),
    responses(
        (status = 200, description = "Get user metadata successfully", body = OkWrapper<GetUserMetadataRes>),
        (status = 404, description = "User metadata not found", body = ErrorWrapper<GetUserMetadataRes>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<GetUserMetadataRes>)
    )
)]
#[web::get("/metadata/{user_principal}")]
async fn get_user_metadata(
    state: State<AppState>,
    path: Path<Principal>,
) -> Result<Json<ApiResult<GetUserMetadataRes>>> {
    let result = get_user_metadata_impl(&state.redis, *path).await?;
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
    path = "/metadata/bulk-get",
    request_body = BulkGetUserMetadataReq,
    responses(
        (status = 200, description = "Get user metadata in bulk successfully", body = String, content_type = "application/json"),
        (status = 500, description = "Internal server error", body = ErrorWrapper<String>)
    )
)]
#[web::post("/metadata/bulk-get")]
async fn get_user_metadata_bulk(
    state: State<AppState>,
    req: Json<BulkGetUserMetadataReq>,
) -> Result<Json<ApiResult<BulkGetUserMetadataRes>>> {
    let result = get_user_metadata_bulk_impl(&state.redis, req.0)
        .await
        .map_err(|e| {
            log::error!("Error fetching bulk user metadata: {}", e);
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
