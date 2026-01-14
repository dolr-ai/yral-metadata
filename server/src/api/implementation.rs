use bb8::PooledConnection;
use bb8_redis::RedisConnectionManager;
use candid::Principal;
use elsa::sync::FrozenVec;
use futures::{stream, StreamExt, TryStreamExt};
use redis::{
    aio::{ConnectionManager, MultiplexedConnection},
    AsyncCommands,
};
use regex::Regex;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};
use types::{
    BulkGetUserMetadataReq, BulkGetUserMetadataRes, BulkUsers, CanisterToPrincipalReq,
    CanisterToPrincipalRes, GetUserMetadataRes, GetUserMetadataV2Res, SetUserMetadataReq,
    SetUserMetadataReqMetadata, SetUserMetadataRes, UserMetadata, UserMetadataByUsername,
    UserMetadataV2,
};

use crate::{
    dragonfly::{format_to_dragonfly_key, DragonflyPool},
    state::RedisPool,
    utils::error::{Error, Result},
};

pub const METADATA_FIELD: &str = "metadata";

pub fn username_info_key(user_name: &str) -> String {
    format!("username-info:{}", user_name)
}

async fn set_metadata_for_username(
    conn: &mut PooledConnection<'_, RedisConnectionManager>,
    dragonfly_conn: &mut MultiplexedConnection,
    user_principal: Principal,
    user_name: String,
    key_prefix: &str,
) -> Result<()> {
    static USERNAME_REGEX: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^([a-zA-Z0-9]){3,15}$").unwrap());

    if !USERNAME_REGEX.is_match(&user_name) {
        return Err(Error::InvalidUsername);
    }

    let key = username_info_key(&user_name);
    let formatted_key = format_to_dragonfly_key(key_prefix, &key);
    let meta = UserMetadataByUsername { user_principal };
    let meta_raw = serde_json::to_vec(&meta).map_err(Error::Deser)?;

    let inserted: usize = conn.hset_nx(&key, METADATA_FIELD, &meta_raw).await?;
    let d_inserted: usize = dragonfly_conn
        .hset_nx(&formatted_key, METADATA_FIELD, &meta_raw)
        .await?;
    if inserted != 1 && d_inserted != 1 {
        return Err(Error::DuplicateUsername);
    }

    Ok(())
}

/// Core implementation for setting user metadata (without signature verification)
/// This is the actual business logic after authentication/authorization
pub async fn set_user_metadata_core(
    redis_pool: &RedisPool,
    dragonfly_pool: &DragonflyPool,
    user_principal: Principal,
    set_metadata: &SetUserMetadataReqMetadata,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<SetUserMetadataRes> {
    let user = user_principal.to_text();
    let mut conn = redis_pool.get().await?;
    let mut dragonfly_conn = dragonfly_pool.get().await?;

    let existing_meta: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;

    if !set_metadata.user_name.is_empty() {
        set_metadata_for_username(
            &mut conn,
            &mut dragonfly_conn,
            user_principal,
            set_metadata.user_name.clone(),
            key_prefix,
        )
        .await?;
    }

    let new_meta = if let Some(existing_meta) = existing_meta {
        let mut existing: UserMetadata =
            serde_json::from_slice(&existing_meta).map_err(Error::Deser)?;
        existing.user_canister_id = set_metadata.user_canister_id;

        if !set_metadata.user_name.is_empty() {
            if !existing.user_name.is_empty() {
                let key = username_info_key(&existing.user_name);
                let _del: usize = conn.hdel(&key, METADATA_FIELD).await?;
                let _d_del: usize = dragonfly_conn
                    .hdel(&format_to_dragonfly_key(key_prefix, &key), METADATA_FIELD)
                    .await?;
            }
            existing.user_name = set_metadata.user_name.clone();
        }

        existing
    } else {
        UserMetadata {
            user_canister_id: set_metadata.user_canister_id,
            user_name: set_metadata.user_name.clone(),
            notification_key: None,
            is_migrated: false,
            email: None,
            signup_at: None,
        }
    };

    // Serialize metadata
    let meta_raw = serde_json::to_vec(&new_meta).map_err(Error::Deser)?;

    // Store user metadata
    let _replaced: bool = conn.hset(&user, METADATA_FIELD, &meta_raw).await?;
    let _d_replaced: bool = dragonfly_conn
        .hset(
            &format_to_dragonfly_key(key_prefix, &user),
            METADATA_FIELD,
            &meta_raw,
        )
        .await?;

    // Update reverse index: canister_id -> user_principal
    let _: bool = conn
        .hset(can2prin_key, new_meta.user_canister_id.to_text(), &user)
        .await?;

    Ok(())
}

/// Core implementation for setting user metadata
pub async fn set_user_metadata_impl(
    redis_pool: &RedisPool,
    dragonfly_pool: &DragonflyPool,
    user_principal: Principal,
    req: SetUserMetadataReq,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<SetUserMetadataRes> {
    // Verify signature
    req.signature.verify_identity(
        user_principal,
        req.metadata
            .clone()
            .try_into()
            .map_err(|_| Error::AuthTokenMissing)?,
    )?;

    // Call core implementation
    set_user_metadata_core(
        redis_pool,
        dragonfly_pool,
        user_principal,
        &req.metadata,
        can2prin_key,
        key_prefix,
    )
    .await
}

pub async fn set_user_metadata_using_admin_identity_impl(
    redis_pool: &RedisPool,
    dragonfly_pool: &DragonflyPool,
    admin_principal: Principal,
    user_principal: Principal,
    req: SetUserMetadataReq,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<SetUserMetadataRes> {
    // Verify signature
    req.signature.verify_identity(
        admin_principal,
        req.metadata
            .clone()
            .try_into()
            .map_err(|_| Error::AuthTokenMissing)?,
    )?;

    // Call core implementation
    set_user_metadata_core(
        redis_pool,
        dragonfly_pool,
        user_principal,
        &req.metadata,
        can2prin_key,
        key_prefix,
    )
    .await
}

/// Core implementation for getting user metadata
pub async fn get_user_metadata_impl(
    redis_pool: &RedisPool,
    dragonfly_pool: &DragonflyPool,
    username_or_principal: String,
    key_prefix: &str,
) -> Result<GetUserMetadataV2Res> {
    let mut conn = redis_pool.get().await?;
    let mut dragonfly_conn = dragonfly_pool.get().await?;
    let user_principal = if let Ok(principal) = Principal::from_text(username_or_principal.as_str())
    {
        principal
    } else {
        let key = username_info_key(username_or_principal.as_str());
        let meta_raw: Option<Box<[u8]>> = conn.hget(&key, METADATA_FIELD).await?;
        let Some(meta_raw) = meta_raw else {
            return Ok(None);
        };
        let meta: UserMetadataByUsername =
            serde_json::from_slice(&meta_raw).map_err(Error::Deser)?;
        meta.user_principal
    };

    let meta_raw: Option<Box<[u8]>> = conn.hget(&user_principal.to_text(), METADATA_FIELD).await?;

    match meta_raw {
        Some(raw) => {
            let meta: UserMetadata = serde_json::from_slice(&raw).map_err(Error::Deser)?;
            Ok(Some(UserMetadataV2::from_metadata(user_principal, meta)))
        }
        None => Ok(None),
    }
}

/// Core implementation for bulk delete of user metadata
pub async fn delete_metadata_bulk_impl(
    redis_pool: &RedisPool,
    dragonfly_pool: &DragonflyPool,
    users: &BulkUsers,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<()> {
    let keys = users.users.iter().map(|k| k.to_text()).collect::<Vec<_>>();
    let formatted_keys = keys
        .iter()
        .map(|k| format_to_dragonfly_key(key_prefix, k))
        .collect::<Vec<_>>();

    let canister_ids: Arc<FrozenVec<String>> = Arc::new(FrozenVec::new());
    let usernames: Arc<FrozenVec<String>> = Arc::new(FrozenVec::new());

    let conn = redis_pool.get().await?;
    let mut dragonfly_conn = dragonfly_pool.get().await?;
    let mut inner_stream = stream::iter(users.users.iter().copied())
        .map(|user_principal| {
            let mut conn = conn.clone();
            let canister_ids = canister_ids.clone();
            let usernames = usernames.clone();
            async move {
                let user = user_principal.to_text();
                let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
                let Some(meta_raw) = meta_raw else {
                    return Ok::<(), Error>(());
                };

                let meta: UserMetadata = serde_json::from_slice(&meta_raw).map_err(Error::Deser)?;
                canister_ids.push(meta.user_canister_id.to_text());
                if !meta.user_name.is_empty() {
                    usernames.push(username_info_key(meta.user_name.as_str()));
                }

                Ok(())
            }
        })
        .buffer_unordered(25); // Process up to 25 requests concurrently (being conservative here)

    while let Some(_) = inner_stream.try_next().await? {}
    std::mem::drop(inner_stream);

    let canister_ids = Arc::try_unwrap(canister_ids)
        .map_err(|_| ())
        .expect("[BUG] CONCURRENCY: All refs to canister_ids should be dropped before this point")
        .into_vec();
    let usernames = Arc::try_unwrap(usernames)
        .map_err(|_| ())
        .expect("[BUG] CONCURRENCY: All refs to usernames should be dropped before this point")
        .into_vec();

    let formatted_canister_ids: Vec<String> = canister_ids
        .iter()
        .map(|id| format_to_dragonfly_key(key_prefix, id))
        .collect();

    let formatted_usernames: Vec<String> = usernames
        .iter()
        .map(|name| format_to_dragonfly_key(key_prefix, name))
        .collect();

    // Delete user metadata
    let chunk_size = 1000;
    let mut failed = 0;
    let mut conn = redis_pool.get().await?;
    for chunk in keys.chunks(chunk_size) {
        let res: usize = conn.del(chunk).await?;
        failed += chunk.len() - res as usize;
    }

    for chunk in formatted_keys.chunks(chunk_size) {
        let res: usize = dragonfly_conn.del(chunk).await?;
    }

    // Also remove from reverse index
    if !canister_ids.is_empty() {
        for chunk in canister_ids.chunks(chunk_size) {
            let _: usize = conn.hdel(can2prin_key, chunk).await?;
        }
    }

    if !formatted_canister_ids.is_empty() {
        for chunk in formatted_canister_ids.chunks(chunk_size) {
            let _: usize = dragonfly_conn
                .hdel(&format_to_dragonfly_key(key_prefix, can2prin_key), chunk)
                .await?;
        }
    }

    // remove unused usernames
    if !usernames.is_empty() {
        for chunk in usernames.chunks(chunk_size) {
            let _: usize = conn.del(chunk).await?;
        }
    }

    if !formatted_usernames.is_empty() {
        for chunk in formatted_usernames.chunks(chunk_size) {
            let _: usize = dragonfly_conn.del(chunk).await?;
        }
    }

    if failed > 0 {
        return Err(Error::Unknown(format!("failed to delete {} keys", failed)));
    }

    Ok(())
}

/// Core implementation for bulk get of user metadata
pub async fn get_user_metadata_bulk_impl(
    redis_pool: &RedisPool,
    dragonfly_pool: &DragonflyPool,
    req: BulkGetUserMetadataReq,
    key_prefix: &str,
) -> Result<BulkGetUserMetadataRes> {
    // Create a stream of futures that fetch metadata for each principal
    let futures_stream = stream::iter(req.users.iter().cloned())
        .map(|principal| {
            let redis_pool = redis_pool.clone();
            let dragonfly_pool = dragonfly_pool.clone();
            async move {
                let user = principal.to_text();

                // Get a new connection for this operation
                let mut conn = redis_pool.get().await?;
                let mut dconn = dragonfly_pool.get().await?;
                let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;

                let metadata = match meta_raw {
                    Some(raw) => {
                        let meta: UserMetadata =
                            serde_json::from_slice(&raw).map_err(Error::Deser)?;
                        Some(meta)
                    }
                    None => None,
                };

                Ok::<(Principal, GetUserMetadataRes), Error>((principal, metadata))
            }
        })
        .buffer_unordered(10); // Process up to 10 requests concurrently

    // Collect all results into a HashMap
    let results: HashMap<Principal, GetUserMetadataRes> = futures_stream.try_collect().await?;

    Ok(results)
}

/// Core implementation for bulk canister to principal lookup
pub async fn get_canister_to_principal_bulk_impl(
    redis_pool: &RedisPool,
    dragonfly_pool: &DragonflyPool,
    req: CanisterToPrincipalReq,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<CanisterToPrincipalRes> {
    // Handle empty request
    if req.canisters.is_empty() {
        return Ok(CanisterToPrincipalRes {
            mappings: HashMap::new(),
        });
    }

    let mut conn = redis_pool.get().await?;
    let mut dragonfly_conn = dragonfly_pool.get().await?;
    let mut mappings = HashMap::new();

    // Process in batches to avoid potential issues with very large requests
    const BATCH_SIZE: usize = 1000;

    for batch in req.canisters.chunks(BATCH_SIZE) {
        // Convert canister IDs to strings for Redis
        let canister_ids: Vec<String> = batch.iter().map(|c| c.to_text()).collect();

        // Use HMGET to fetch multiple values at once from the Redis hash
        let values: Vec<Option<String>> = conn.hmget(can2prin_key, &canister_ids).await?;

        // Process results for this batch
        for (i, canister_id) in batch.iter().enumerate() {
            if let Some(Some(principal_str)) = values.get(i) {
                if let Ok(user_principal) = Principal::from_text(principal_str) {
                    mappings.insert(*canister_id, user_principal);
                }
            }
        }
    }

    Ok(CanisterToPrincipalRes { mappings })
}
