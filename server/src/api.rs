use candid::Principal;
use futures::{prelude::*, stream::FuturesUnordered};
use ntex::web::{
    self,
    types::{Json, Path, State},
};
use redis::{AsyncCommands, RedisError};
use types::{
    error::ApiError, ApiResult, BulkUsers, GetUserMetadataRes, SetUserMetadataReq,
    SetUserMetadataRes, UserMetadata,
};

use crate::{
    auth::verify_token,
    services::error_wrappers::{ErrorWrapper, NullOk, OkWrapper},
    state::AppState,
    utils::error::{Error, Result},
};

pub const METADATA_FIELD: &str = "metadata";

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
    let signature = req.0.signature;
    let metadata = req.0.metadata;
    signature.verify_identity(
        *user_principal,
        metadata
            .clone()
            .try_into()
            .map_err(|_| Error::AuthTokenMissing)?,
    )?;

    let user = user_principal.to_text();
    let mut conn = state.redis.get().await?;
    let meta_raw = serde_json::to_vec(&metadata).map_err(Error::Deser)?;
    let _replaced: bool = conn.hset(user, METADATA_FIELD, &meta_raw).await?;

    Ok(Json(Ok(())))
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
    let user = path.to_text();

    let mut conn = state.redis.get().await?;
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
    let Some(meta_raw) = meta_raw else {
        return Ok(Json(Ok(None)));
    };
    let meta: UserMetadata = serde_json::from_slice(&meta_raw).map_err(Error::Deser)?;

    Ok(Json(Ok(Some(meta))))
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
    verify_token(token, &state.jwt_details)?;

    let keys = req.users.iter().map(|k| k.to_text()).collect::<Vec<_>>();

    let mut conn = state.redis.get().await?;

    let chunk_size = 1000;
    let mut failed = 0;
    for chunk in keys.chunks(chunk_size) {
        let res: usize = conn.del(chunk).await?;
        failed += chunk.len() - res as usize;
    }

    if failed > 0 {
        return Err(Error::Unknown(format!("failed to delete {} keys", failed)));
    }

    Ok(Json(Ok(())))
}
