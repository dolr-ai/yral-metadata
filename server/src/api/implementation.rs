use candid::Principal;
use redis::AsyncCommands;
use std::collections::HashMap;
use types::{
    BulkGetUserMetadataReq, BulkGetUserMetadataRes, BulkUsers, CanisterToPrincipalReq,
    CanisterToPrincipalRes, GetUserMetadataRes, SetUserMetadataReq, SetUserMetadataReqMetadata,
    SetUserMetadataRes, UserMetadata,
};
use futures::{stream, StreamExt, TryStreamExt};

use crate::{
    state::RedisPool,
    utils::{
        canister::CANISTER_TO_PRINCIPAL_KEY,
        error::{Error, Result},
    },
};

pub const METADATA_FIELD: &str = "metadata";

/// Core implementation for setting user metadata (without signature verification)
/// This is the actual business logic after authentication/authorization
pub async fn set_user_metadata_core(
    redis_pool: &RedisPool,
    user_principal: Principal,
    metadata: &SetUserMetadataReqMetadata,
) -> Result<SetUserMetadataRes> {
    let user = user_principal.to_text();
    let mut conn = redis_pool.get().await?;
    
    // Serialize metadata
    let meta_raw = serde_json::to_vec(metadata).map_err(Error::Deser)?;
    
    // Store user metadata
    let _replaced: bool = conn.hset(&user, METADATA_FIELD, &meta_raw).await?;
    
    // Update reverse index: canister_id -> user_principal
    let _: bool = conn
        .hset(
            CANISTER_TO_PRINCIPAL_KEY,
            metadata.user_canister_id.to_text(),
            &user,
        )
        .await?;

    Ok(())
}

/// Core implementation for setting user metadata
pub async fn set_user_metadata_impl(
    redis_pool: &RedisPool,
    user_principal: Principal,
    req: SetUserMetadataReq,
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
    set_user_metadata_core(redis_pool, user_principal, &req.metadata).await
}

/// Core implementation for getting user metadata
pub async fn get_user_metadata_impl(
    redis_pool: &RedisPool,
    user_principal: Principal,
) -> Result<GetUserMetadataRes> {
    let user = user_principal.to_text();
    let mut conn = redis_pool.get().await?;
    
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
    
    match meta_raw {
        Some(raw) => {
            let meta: UserMetadata = serde_json::from_slice(&raw).map_err(Error::Deser)?;
            Ok(Some(meta))
        }
        None => Ok(None),
    }
}

/// Core implementation for bulk delete of user metadata
pub async fn delete_metadata_bulk_impl(
    redis_pool: &RedisPool,
    users: BulkUsers,
) -> Result<()> {
    let keys = users.users.iter().map(|k| k.to_text()).collect::<Vec<_>>();
    let mut conn = redis_pool.get().await?;

    // First, collect canister IDs before deletion
    let mut canister_ids = Vec::new();
    for user_principal in &users.users {
        let user = user_principal.to_text();
        if let Ok(Some(meta_raw)) = conn.hget::<_, _, Option<Box<[u8]>>>(&user, METADATA_FIELD).await {
            if let Ok(meta) = serde_json::from_slice::<UserMetadata>(&meta_raw) {
                canister_ids.push(meta.user_canister_id.to_text());
            }
        }
    }

    // Delete user metadata
    let chunk_size = 1000;
    let mut failed = 0;
    for chunk in keys.chunks(chunk_size) {
        let res: usize = conn.del(chunk).await?;
        failed += chunk.len() - res as usize;
    }

    // Also remove from reverse index
    if !canister_ids.is_empty() {
        for chunk in canister_ids.chunks(chunk_size) {
            let _: usize = conn.hdel(CANISTER_TO_PRINCIPAL_KEY, chunk).await?;
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
    req: BulkGetUserMetadataReq,
) -> Result<BulkGetUserMetadataRes> {
    // Create a stream of futures that fetch metadata for each principal
    let futures_stream = stream::iter(req.users.iter().cloned())
        .map(|principal| {
            let redis_pool = redis_pool.clone();
            async move {
                let user = principal.to_text();
                
                // Get a new connection for this operation
                let mut conn = redis_pool.get().await?;
                let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
                
                let metadata = match meta_raw {
                    Some(raw) => {
                        let meta: UserMetadata = serde_json::from_slice(&raw).map_err(Error::Deser)?;
                        Some(meta)
                    }
                    None => None,
                };
                
                Ok::<(Principal, GetUserMetadataRes), Error>((principal, metadata))
            }
        })
        .buffer_unordered(10); // Process up to 10 requests concurrently
    
    // Collect all results into a HashMap
    let results: HashMap<Principal, GetUserMetadataRes> = futures_stream
        .try_collect()
        .await?;
    
    Ok(results)
}

/// Core implementation for bulk canister to principal lookup
pub async fn get_canister_to_principal_bulk_impl(
    redis_pool: &RedisPool,
    req: CanisterToPrincipalReq,
) -> Result<CanisterToPrincipalRes> {
    // Handle empty request
    if req.canisters.is_empty() {
        return Ok(CanisterToPrincipalRes { mappings: HashMap::new() });
    }
    
    let mut conn = redis_pool.get().await?;
    let mut mappings = HashMap::new();
    
    // Process in batches to avoid potential issues with very large requests
    const BATCH_SIZE: usize = 1000;
    
    for batch in req.canisters.chunks(BATCH_SIZE) {
        // Convert canister IDs to strings for Redis
        let canister_ids: Vec<String> = batch.iter().map(|c| c.to_text()).collect();
        
        // Use HMGET to fetch multiple values at once from the Redis hash
        let values: Vec<Option<String>> = conn.hget(CANISTER_TO_PRINCIPAL_KEY, &canister_ids).await?;
        
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