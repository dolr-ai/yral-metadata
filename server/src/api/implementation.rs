use bb8::PooledConnection;
use bb8_redis::RedisConnectionManager;
use candid::Principal;
use redis::{aio::MultiplexedConnection, AsyncCommands};
use regex::Regex;
use std::{collections::HashMap, sync::LazyLock};
use types::{
    BulkGetUserMetadataReq, BulkGetUserMetadataRes, BulkUsers, CanisterToPrincipalReq,
    CanisterToPrincipalRes, GetUserMetadataV2Res, SetUserMetadataReq, SetUserMetadataReqMetadata,
    SetUserMetadataRes, UserMetadata, UserMetadataByUsername, UserMetadataV2,
};

use crate::{
    dragonfly::{format_to_dragonfly_key, DragonflyPool},
    utils::error::{Error, Result},
};

pub const METADATA_FIELD: &str = "metadata";

pub fn username_info_key(user_name: &str) -> String {
    format!("username-info:{}", user_name)
}

async fn set_metadata_for_username(
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

    let d_inserted: usize = dragonfly_conn
        .hset_nx(&formatted_key, METADATA_FIELD, &meta_raw)
        .await?;
    if d_inserted != 1 {
        return Err(Error::DuplicateUsername);
    }

    Ok(())
}

/// Core implementation for setting user metadata (without signature verification)
/// This is the actual business logic after authentication/authorization
/// Optimized with Redis pipelines for batch operations
pub async fn set_user_metadata_core(
    dragonfly_pool: &DragonflyPool,
    user_principal: Principal,
    set_metadata: &SetUserMetadataReqMetadata,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<SetUserMetadataRes> {
    let user = user_principal.to_text();
    let mut dragonfly_conn = dragonfly_pool.get().await?;

    let existing_meta: Option<Box<[u8]>> = dragonfly_conn
        .hget(format_to_dragonfly_key(key_prefix, &user), METADATA_FIELD)
        .await?;

    if !set_metadata.user_name.is_empty() {
        set_metadata_for_username(
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
                // Delete old username from both Redis and Dragonfly using pipeline
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

    // Use pipeline for Dragonfly writes (2 operations in one round trip)
    let mut dragonfly_pipe = redis::pipe();
    dragonfly_pipe
        .hset(
            &format_to_dragonfly_key(key_prefix, &user),
            METADATA_FIELD,
            &meta_raw,
        )
        .ignore()
        .hset(
            format_to_dragonfly_key(key_prefix, can2prin_key),
            new_meta.user_canister_id.to_text(),
            &user,
        )
        .ignore();
    dragonfly_pipe
        .query_async::<()>(&mut dragonfly_conn)
        .await?;

    Ok(())
}

/// Core implementation for setting user metadata
pub async fn set_user_metadata_impl(
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
        dragonfly_pool,
        user_principal,
        &req.metadata,
        can2prin_key,
        key_prefix,
    )
    .await
}

pub async fn set_user_metadata_using_admin_identity_impl(
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
    dragonfly_pool: &DragonflyPool,
    username_or_principal: String,
    key_prefix: &str,
) -> Result<GetUserMetadataV2Res> {
    let mut d_conn = dragonfly_pool.get().await?;
    let user_principal = if let Ok(principal) = Principal::from_text(username_or_principal.as_str())
    {
        principal
    } else {
        let key = username_info_key(username_or_principal.as_str());
        let meta_raw: Option<Box<[u8]>> = d_conn
            .hget(format_to_dragonfly_key(key_prefix, &key), METADATA_FIELD)
            .await?;
        let Some(meta_raw) = meta_raw else {
            return Ok(None);
        };
        let meta: UserMetadataByUsername =
            serde_json::from_slice(&meta_raw).map_err(Error::Deser)?;
        meta.user_principal
    };

    let meta_raw: Option<Box<[u8]>> = d_conn
        .hget(
            format_to_dragonfly_key(key_prefix, &user_principal.to_text()),
            METADATA_FIELD,
        )
        .await?;

    match meta_raw {
        Some(raw) => {
            let meta: UserMetadata = serde_json::from_slice(&raw).map_err(Error::Deser)?;
            Ok(Some(UserMetadataV2::from_metadata(user_principal, meta)))
        }
        None => Ok(None),
    }
}

/// Core implementation for bulk delete of user metadata
/// Optimized with Redis pipelines for batch operations
pub async fn delete_metadata_bulk_impl(
    dragonfly_pool: &DragonflyPool,
    users: &BulkUsers,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<()> {
    if users.users.is_empty() {
        return Ok(());
    }

    let keys: Vec<String> = users.users.iter().map(|k| k.to_text()).collect();
    let formatted_keys: Vec<String> = keys
        .iter()
        .map(|k| format_to_dragonfly_key(key_prefix, k))
        .collect();

    let mut dragonfly_conn = dragonfly_pool.get().await?;

    // Step 1: Fetch all metadata using batched pipeline (chunks of 200 to avoid timeout)
    const BATCH_SIZE: usize = 200;
    let mut metadata_results: Vec<Option<Vec<u8>>> = Vec::with_capacity(keys.len());

    for chunk in keys.chunks(BATCH_SIZE) {
        let mut fetch_pipe = redis::pipe();
        for key in chunk {
            fetch_pipe.hget(format_to_dragonfly_key(key_prefix, &key), METADATA_FIELD);
        }
        let chunk_results: Vec<Option<Vec<u8>>> =
            fetch_pipe.query_async(&mut dragonfly_conn).await?;
        metadata_results.extend(chunk_results);
    }

    // Collect canister IDs and usernames to delete
    let mut canister_ids = Vec::new();
    let mut usernames = Vec::new();

    for meta_raw in metadata_results.into_iter().flatten() {
        if let Ok(meta) = serde_json::from_slice::<UserMetadata>(&meta_raw) {
            canister_ids.push(meta.user_canister_id.to_text());
            if !meta.user_name.is_empty() {
                usernames.push(username_info_key(&meta.user_name));
            }
        }
    }

    let formatted_usernames: Vec<String> = usernames
        .iter()
        .map(|name| format_to_dragonfly_key(key_prefix, name))
        .collect();

    // Step 2: Delete from Dragonfly in batches
    // Delete user metadata keys in chunks
    for chunk in formatted_keys.chunks(BATCH_SIZE) {
        let mut pipe = redis::pipe();
        pipe.del(chunk).ignore();
        pipe.query_async::<()>(&mut dragonfly_conn).await?;
    }

    // Delete from reverse index in chunks
    for chunk in canister_ids.chunks(BATCH_SIZE) {
        let mut pipe = redis::pipe();
        pipe.hdel(&format_to_dragonfly_key(key_prefix, can2prin_key), chunk)
            .ignore();
        pipe.query_async::<()>(&mut dragonfly_conn).await?;
    }

    // Delete usernames in chunks
    for chunk in formatted_usernames.chunks(BATCH_SIZE) {
        let mut pipe = redis::pipe();
        pipe.del(chunk).ignore();
        pipe.query_async::<()>(&mut dragonfly_conn).await?;
    }

    Ok(())
}

/// Core implementation for bulk get of user metadata
/// Optimized with Redis pipeline for batch HGET operations
pub async fn get_user_metadata_bulk_impl(
    dragonfly_pool: &DragonflyPool,
    req: BulkGetUserMetadataReq,
    key_prefix: &str,
) -> Result<BulkGetUserMetadataRes> {
    if req.users.is_empty() {
        return Ok(HashMap::new());
    }

    let mut dconn = dragonfly_pool.get().await?;

    // Build pipeline for all HGET operations (one round trip for all users)
    let mut pipe = redis::pipe();
    for principal in &req.users {
        pipe.hget(
            format_to_dragonfly_key(key_prefix, &principal.to_text()),
            METADATA_FIELD,
        );
    }

    // Execute pipeline and get all results
    let results: Vec<Option<Vec<u8>>> = pipe.query_async(&mut dconn).await?;

    // Build result map
    let mut result_map = HashMap::with_capacity(req.users.len());
    for (principal, meta_raw) in req.users.iter().zip(results.into_iter()) {
        let metadata = match meta_raw {
            Some(raw) => {
                let meta: UserMetadata = serde_json::from_slice(&raw).map_err(Error::Deser)?;
                Some(meta)
            }
            None => None,
        };
        result_map.insert(*principal, metadata);
    }

    Ok(result_map)
}

/// Core implementation for bulk canister to principal lookup
pub async fn get_canister_to_principal_bulk_impl(
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

    let mut dconn = dragonfly_pool.get().await?;
    let mut mappings = HashMap::new();

    // Process in batches to avoid timeout on remote Redis
    const BATCH_SIZE: usize = 200;

    for batch in req.canisters.chunks(BATCH_SIZE) {
        // Convert canister IDs to strings for Redis
        let canister_ids: Vec<String> = batch.iter().map(|c| c.to_text()).collect();

        // Use HMGET to fetch multiple values at once from the Redis hash
        let values: Vec<Option<String>> = dconn
            .hmget(
                format_to_dragonfly_key(key_prefix, can2prin_key),
                &canister_ids,
            )
            .await?;

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
