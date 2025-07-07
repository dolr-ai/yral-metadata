use std::sync::LazyLock;

use bb8::PooledConnection;
use bb8_redis::RedisConnectionManager;
use candid::Principal;
use futures::{prelude::*, stream::FuturesUnordered};
use ntex::web::{
    self,
    types::{Json, Path, State},
};
use redis::{AsyncCommands, RedisError};
use regex::Regex;
use types::{
    error::ApiError, ApiResult, BulkUsers, GetUserMetadataRes, SetUserMetadataReq, SetUserMetadataRes, UserMetadata, UserMetadataByUsername, UserMetadataV2
};

use crate::{
    auth::verify_token,
    services::error_wrappers::{ErrorWrapper, NullOk, OkWrapper},
    state::AppState,
    utils::error::{Error, Result},
};

pub const METADATA_FIELD: &str = "metadata";

fn username_info_key(user_name: &str) -> String {
    format!("username-info:{}", user_name)
}

async fn set_metadata_for_username(
    conn: &mut PooledConnection<'_, RedisConnectionManager>,
    user_principal: Principal,
    user_name: String,
) -> Result<()> {
    static USERNAME_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^([a-zA-Z0-9]){3,15}$").unwrap());
    if !USERNAME_REGEX.is_match(&user_name) {
        return Err(Error::InvalidUsername);
    }

    let key = username_info_key(&user_name);
    let meta = UserMetadataByUsername {
        user_principal,
    };
    let meta_raw = serde_json::to_vec(&meta).map_err(Error::Deser)?;
    let inserted: usize = conn.hset_nx(&key, METADATA_FIELD, &meta_raw).await?;
    if inserted != 1 {
        return Err(Error::DuplicateUsername);
    }

    Ok(())
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
#[web::post("/metadata/{user_principal}")]
async fn set_user_metadata(
    state: State<AppState>,
    user_principal: Path<Principal>,
    req: Json<SetUserMetadataReq>,
) -> Result<Json<ApiResult<SetUserMetadataRes>>> {
    let signature = req.0.signature;
    let set_metadata = req.0.metadata;
    signature.verify_identity(
        *user_principal,
        set_metadata
            .clone()
            .try_into()
            .map_err(|_| Error::AuthTokenMissing)?,
    )?;

    let user = user_principal.to_text();
    let mut conn = state.redis.get().await?;

    let existing_meta: Option<Box<[u8]>> = conn
        .hget(&user, METADATA_FIELD)
        .await?;

    let new_meta = if let Some(existing_meta) = existing_meta {
        let mut existing: UserMetadata = serde_json::from_slice(&existing_meta)
            .map_err(Error::Deser)?;
        existing.user_canister_id = set_metadata.user_canister_id;

        if set_metadata.user_name.is_empty() {
            let meta_raw = serde_json::to_vec(&existing).map_err(Error::Deser)?;
            let _replaced: bool = conn.hset(user, METADATA_FIELD, &meta_raw).await?;
            return Ok(Json(Ok(())));
        }

        set_metadata_for_username(&mut conn, *user_principal, set_metadata.user_name.clone())
            .await?;
        if !existing.user_name.is_empty() {
            let key = username_info_key(&existing.user_name);
            let _del: usize = conn.hdel(&key, METADATA_FIELD).await?;
        }
        existing.user_name = set_metadata.user_name.clone();
        existing
    } else {
        if !set_metadata.user_name.is_empty() {
            set_metadata_for_username(&mut conn, *user_principal, set_metadata.user_name.clone())
                .await?;
        }

        let meta: UserMetadata = UserMetadata { 
            user_canister_id: set_metadata.user_canister_id,
            user_name: set_metadata.user_name,
            notification_key: None,
            is_migrated: false
        };
        meta
    };

    let meta_raw = serde_json::to_vec(&new_meta).map_err(Error::Deser)?;
    let _replaced: bool = conn.hset(user, METADATA_FIELD, &meta_raw).await?;

    Ok(Json(Ok(())))
}

async fn get_user_metadata_inner(
    conn: &mut PooledConnection<'_, RedisConnectionManager>,
    user: &str,
) -> Result<Option<UserMetadata>> {
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
    let Some(meta_raw) = meta_raw else {
        return Ok(None);
    };
    let meta: UserMetadata = serde_json::from_slice(&meta_raw).map_err(Error::Deser)?;

    Ok(Some(meta))
}

#[utoipa::path(
    get,
    path = "/metadata/{user_principal_or_principal}",
    params(
        ("username_or_principal" = String, Path, description = "Username or principal ID")
    ),
    responses(
        (status = 200, description = "Get user metadata successfully", body = OkWrapper<GetUserMetadataRes>),
        (status = 404, description = "User metadata not found", body = ErrorWrapper<GetUserMetadataRes>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<GetUserMetadataRes>)
    )
)]
#[web::get("/metadata/{username_or_principal}")]
async fn get_user_metadata(
    state: State<AppState>,
    username_or_principal: Path<String>,
) -> Result<Json<ApiResult<GetUserMetadataRes>>> {
    let mut conn = state.redis.get().await?;
    let user_principal = if let Ok(principal) = Principal::from_text(username_or_principal.as_str()) {
        principal
    } else {
       let key = username_info_key(username_or_principal.as_str());
       let meta_raw: Option<Box<[u8]>> = conn.hget(&key, METADATA_FIELD).await?;
       let Some(meta_raw) = meta_raw else {
            return Ok(Json(Ok(None)));
       };
       let meta: UserMetadataByUsername = serde_json::from_slice(&meta_raw).map_err(Error::Deser)?;
       meta.user_principal
    };

    let Some(metadata) = get_user_metadata_inner(&mut conn, &user_principal.to_text()).await? else {
        return Ok(Json(Ok(None)));
    };

    Ok(Json(Ok(Some(UserMetadataV2::from_metadata(user_principal, metadata)))))
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
