use candid::Principal;
use std::{collections::HashMap, sync::LazyLock};
use types::{
    BulkGetUserMetadataReq, BulkGetUserMetadataRes, BulkUsers, CanisterToPrincipalReq,
    CanisterToPrincipalRes, GetUserMetadataV2Res, SetUserMetadataReq, SetUserMetadataReqMetadata,
    SetUserMetadataRes, UserMetadata, UserMetadataByUsername, UserMetadataV2,
};
use regex::Regex;

use crate::{
    api::store::MetadataKvStore,
    dragonfly::format_to_dragonfly_key,
    utils::error::{Error, Result},
};

pub const METADATA_FIELD: &str = "metadata";

pub fn username_info_key(user_name: &str) -> String {
    format!("username-info:{}", user_name)
}

/// Core implementation for setting user metadata (without signature verification).
pub async fn set_user_metadata_core<S: MetadataKvStore>(
    store: &S,
    new_store: &S,
    user_principal: Principal,
    set_metadata: &SetUserMetadataReqMetadata,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<SetUserMetadataRes> {
    let user_key = format_to_dragonfly_key(key_prefix, &user_principal.to_text());
    let can2prin_key_fmt = format_to_dragonfly_key(key_prefix, can2prin_key);

    let existing_bytes = store.hget(&user_key, METADATA_FIELD).await?;

    if !set_metadata.user_name.is_empty() {
        static USERNAME_REGEX: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^([a-zA-Z0-9]){3,15}$").unwrap());

        if !USERNAME_REGEX.is_match(&set_metadata.user_name) {
            return Err(Error::InvalidUsername);
        }

        let username_key =
            format_to_dragonfly_key(key_prefix, &username_info_key(&set_metadata.user_name));
        let meta_raw = serde_json::to_vec(&UserMetadataByUsername { user_principal })
            .map_err(Error::Deser)?;
        let inserted = store.hset_nx(&username_key, METADATA_FIELD, &meta_raw).await?;
        let store_inserted = new_store.hset_nx(&username_key, METADATA_FIELD, &meta_raw).await?;

        if !inserted && !store_inserted {
            return Err(Error::DuplicateUsername);
        }

    }

    let new_meta = if let Some(existing_bytes) = existing_bytes {
        let mut existing: UserMetadata =
            serde_json::from_slice(&existing_bytes).map_err(Error::Deser)?;
        existing.user_canister_id = set_metadata.user_canister_id;

        if !set_metadata.user_name.is_empty() {
            if !existing.user_name.is_empty() {
                let old_key = format_to_dragonfly_key(
                    key_prefix,
                    &username_info_key(&existing.user_name),
                );
                store.hdel(&old_key, METADATA_FIELD).await?;
                new_store.hdel(&old_key, METADATA_FIELD).await?;
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

    let meta_raw = serde_json::to_vec(&new_meta).map_err(Error::Deser)?;
    store.hset(&user_key, METADATA_FIELD, &meta_raw).await?;
    new_store.hset(&user_key, METADATA_FIELD, &meta_raw).await?;

    store
        .hset(
            &can2prin_key_fmt,
            &new_meta.user_canister_id.to_text(),
            user_principal.to_text().as_bytes(),
        )
        .await?;

    new_store
        .hset(
            &can2prin_key_fmt,
            &new_meta.user_canister_id.to_text(),
            user_principal.to_text().as_bytes(),
        )
        .await?;

    Ok(())
}

/// Full handler path: verifies signature then calls core.
pub async fn set_user_metadata_impl<S: MetadataKvStore>(
    store: &S,
    new_store: &S,
    user_principal: Principal,
    req: SetUserMetadataReq,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<SetUserMetadataRes> {
    req.signature.verify_identity(
        user_principal,
        req.metadata
            .clone()
            .try_into()
            .map_err(|_| Error::AuthTokenMissing)?,
    )?;
    set_user_metadata_core(store, new_store, user_principal, &req.metadata, can2prin_key, key_prefix).await
}

pub async fn set_user_metadata_using_admin_identity_impl<S: MetadataKvStore>(
    store: &S,
    new_store: &S,
    admin_principal: Principal,
    user_principal: Principal,
    req: SetUserMetadataReq,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<SetUserMetadataRes> {
    req.signature.verify_identity(
        admin_principal,
        req.metadata
            .clone()
            .try_into()
            .map_err(|_| Error::AuthTokenMissing)?,
    )?;
    set_user_metadata_core(store, new_store, user_principal, &req.metadata, can2prin_key, key_prefix).await
}

/// Core implementation for getting user metadata.
pub async fn get_user_metadata_impl<S: MetadataKvStore>(
    store: &S,
    new_store: &S,
    username_or_principal: String,
    key_prefix: &str,
) -> Result<GetUserMetadataV2Res> {
    let user_principal = if let Ok(p) = Principal::from_text(&username_or_principal) {
        p
    } else {
        let key = format_to_dragonfly_key(key_prefix, &username_info_key(&username_or_principal));
        let raw = store.hget(&key, METADATA_FIELD).await?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let meta: UserMetadataByUsername =
            serde_json::from_slice(&raw).map_err(Error::Deser)?;
        meta.user_principal
    };

    let user_key =
        format_to_dragonfly_key(key_prefix, &user_principal.to_text());
    let raw = store.hget(&user_key, METADATA_FIELD).await?;

    match raw {
        Some(raw) => {
            let meta: UserMetadata = serde_json::from_slice(&raw).map_err(Error::Deser)?;
            Ok(Some(UserMetadataV2::from_metadata(user_principal, meta)))
        }
        None => Ok(None),
    }
}

/// Core implementation for bulk delete of user metadata.
pub async fn delete_metadata_bulk_impl<S: MetadataKvStore>(
    store: &S,
    new_store: &S,
    users: &BulkUsers,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<()> {
    if users.users.is_empty() {
        return Ok(());
    }

    let formatted_keys: Vec<String> = users
        .users
        .iter()
        .map(|p| format_to_dragonfly_key(key_prefix, &p.to_text()))
        .collect();

    // Fetch all metadata to find usernames and canister IDs.
    let metadata_results = store.hget_bulk(&formatted_keys, METADATA_FIELD).await?;

    let mut canister_ids = Vec::new();
    let mut username_keys = Vec::new();
    for meta_raw in metadata_results.into_iter().flatten() {
        if let Ok(meta) = serde_json::from_slice::<UserMetadata>(&meta_raw) {
            canister_ids.push(meta.user_canister_id.to_text());
            if !meta.user_name.is_empty() {
                username_keys.push(format_to_dragonfly_key(
                    key_prefix,
                    &username_info_key(&meta.user_name),
                ));
            }
        }
    }

    // Delete username-info keys BEFORE user metadata keys (retry-safe ordering).
    store.del_bulk(&username_keys).await?;
    new_store.del_bulk(&username_keys).await?;
    store.del_bulk(&formatted_keys).await?;
    new_store.del_bulk(&formatted_keys).await?;

    let can2prin_fmt = format_to_dragonfly_key(key_prefix, can2prin_key);
    store.hdel_bulk(&can2prin_fmt, &canister_ids).await?;
    new_store.hdel_bulk(&can2prin_fmt, &canister_ids).await?;

    Ok(())
}

/// Core implementation for bulk get of user metadata.
pub async fn get_user_metadata_bulk_impl<S: MetadataKvStore>(
    store: &S,
    new_store: &S,
    req: BulkGetUserMetadataReq,
    key_prefix: &str,
) -> Result<BulkGetUserMetadataRes> {
    if req.users.is_empty() {
        return Ok(HashMap::new());
    }

    let keys: Vec<String> = req
        .users
        .iter()
        .map(|p| format_to_dragonfly_key(key_prefix, &p.to_text()))
        .collect();

    let raw_results = store.hget_bulk(&keys, METADATA_FIELD).await?;

    let mut result_map = HashMap::with_capacity(req.users.len());
    for (principal, raw_opt) in req.users.iter().zip(raw_results) {
        let metadata: Option<UserMetadata> = match raw_opt {
            Some(raw) => Some(serde_json::from_slice(&raw).map_err(Error::Deser)?),
            None => None,
        };
        result_map.insert(*principal, metadata);
    }

    Ok(result_map)
}

/// Core implementation for bulk canister-to-principal lookup.
pub async fn get_canister_to_principal_bulk_impl<S: MetadataKvStore>(
    store: &S,
    new_store: &S,
    req: CanisterToPrincipalReq,
    can2prin_key: &str,
    key_prefix: &str,
) -> Result<CanisterToPrincipalRes> {
    if req.canisters.is_empty() {
        return Ok(CanisterToPrincipalRes {
            mappings: HashMap::new(),
        });
    }

    let can2prin_fmt = format_to_dragonfly_key(key_prefix, can2prin_key);
    let canister_ids: Vec<String> = req.canisters.iter().map(|c| c.to_text()).collect();

    let values = store.hmget(&can2prin_fmt, &canister_ids).await?;

    let mut mappings = HashMap::new();
    for (canister_id, principal_str_opt) in req.canisters.iter().zip(values) {
        if let Some(principal_str) = principal_str_opt {
            if let Ok(user_principal) = Principal::from_text(&principal_str) {
                mappings.insert(*canister_id, user_principal);
            }
        }
    }

    Ok(CanisterToPrincipalRes { mappings })
}
