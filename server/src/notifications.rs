use candid::Principal;
use ntex::web::{
    self,
    types::{Json, Path, State},
    HttpRequest,
};
use redis::AsyncCommands;
use std::env;
use types::{
    error::ApiError, ApiResult, DeviceRegistrationToken, NotificationKey, RegisterDeviceReq,
    RegisterDeviceRes, SendNotificationReq, SendNotificationRes, UnregisterDeviceReq,
    UnregisterDeviceRes, UserMetadata,
};
use yral_identity::msg_builder::Message;

use crate::{api::METADATA_FIELD, firebase, state::AppState, Error, Result};

#[web::post("/notifications/{user_principal}")]
async fn register_device(
    state: State<AppState>,
    user_principal: Path<Principal>,
    req: Json<RegisterDeviceReq>,
) -> Result<Json<ApiResult<RegisterDeviceRes>>> {
    let signature = req.0.signature;
    let registration_token = req.0.registration_token;
    signature.verify_identity(
        *user_principal.as_ref(),
        Message::try_from(registration_token.clone())?,
    )?;

    let mut conn = state.redis.get().await?;
    let user = user_principal.to_text();
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
    let mut user_metadata: UserMetadata =
        serde_json::from_slice(&meta_raw.unwrap_or_default()).unwrap_or_default();

    let notification_key_name =
        firebase::notifications::utils::get_notification_key_name_from_principal(&user);

    // Step 1: Determine the Firebase notification_key to use for add/create and the operation type.
    let (key_for_firebase_op, operation_type_str): (Option<String>, String) =
        if let Some(meta_nk) = user_metadata.notification_key.as_ref() {
            log::info!(
                "[register_device] Found existing notification key in metadata for user {}: {}. Will attempt to update.",
                user, meta_nk.key
            );
            // Metadata has a key. Remove old token for same device fingerprint if it exists.
            if let Some(old_token_to_remove) = meta_nk
                .registration_tokens
                .iter()
                .find(|token| token.device_fingerprint == registration_token.device_fingerprint)
                .map(|token| token.token.clone())
            {
                log::info!(
                    "[register_device] Found old token for same fingerprint for user {}. Removing it first.",
                    user
                );
                let remove_data = firebase::notifications::utils::get_remove_request_body(
                    notification_key_name.clone(),
                    meta_nk.key.clone(),
                    old_token_to_remove,
                )?;
                state.firebase.update_notification_devices(remove_data).await?;
            }
            (Some(meta_nk.key.clone()), "add".to_string())
        } else {
            log::info!(
                "[register_device] No notification key in metadata for user {}. Checking Firebase by name.",
                user
            );
            // No key in metadata. Try to GET key by name from Firebase.
            match state.firebase.get_notification_key_by_name(&notification_key_name).await {
                Ok(Some(retrieved_key)) => {
                    log::info!(
                        "[register_device] Retrieved existing key {} for name {} for user {}. Will use 'add'.",
                        retrieved_key, notification_key_name, user
                    );
                    (Some(retrieved_key), "add".to_string())
                }
                Ok(None) => {
                    log::info!(
                        "[register_device] No existing key found on Firebase for name {} for user {}. Will use 'create'.",
                        notification_key_name, user
                    );
                    (None, "create".to_string()) // No key to provide for "create" op itself
                }
                Err(e) => {
                    log::error!(
                        "[register_device] Error retrieving notification key by name {} for user {}: {:?}. Cannot proceed.",
                        notification_key_name, user, e
                    );
                    return Err(e); // Propagate error from GET
                }
            }
        };

    // Step 2: Prepare Firebase request body based on operation_type
    let firebase_request_data = match operation_type_str.as_str() {
        "add" => {
            let key_for_add = key_for_firebase_op.ok_or_else(|| {
                Error::Unknown(
                    "[register_device] Logic error: 'add' operation chosen but no key available".to_string(),
                )
            })?;
            log::info!(
                "[register_device] Preparing 'add' request for user {} with key {}.",
                user, key_for_add
            );
            firebase::notifications::utils::get_add_request_body(
                notification_key_name.clone(),
                key_for_add,
                registration_token.token.clone(),
            )?
        }
        "create" => {
            log::info!("[register_device] Preparing 'create' request for user {}.", user);
            firebase::notifications::utils::get_create_request_body(
                notification_key_name.clone(),
                registration_token.token.clone(),
            )?
        }
        _ => unreachable!("[register_device] Invalid operation_type_str"),
    };

    // Step 3: Call Firebase to update/create notification devices
    log::info!(
        "[register_device] Sending '{}' operation to Firebase for user {}.",
        operation_type_str, user
    );
    let actual_firebase_notification_key = state
        .firebase
        .update_notification_devices(firebase_request_data)
        .await?
        .ok_or_else(|| {
            log::error!(
                "[register_device] Firebase '{}' operation for user {} (name: {}) did not return a key.",
                operation_type_str, user, notification_key_name
            );
            Error::Unknown(format!(
                "Firebase '{}' operation for notification key name {} did not return a notification key.",
                operation_type_str, notification_key_name
            ))
        })?;
    log::info!(
        "[register_device] Firebase operation '{}' successful for user {}. Received key: {}",
        operation_type_str, user, actual_firebase_notification_key
    );

    // Step 4: Update metadata
    match user_metadata.notification_key.as_mut() {
        Some(meta) => {
            meta.key = actual_firebase_notification_key;
            meta.registration_tokens
                .retain(|token| token.device_fingerprint != registration_token.device_fingerprint);
            meta.registration_tokens.push(DeviceRegistrationToken {
                token: registration_token.token.clone(),
                device_fingerprint: registration_token.device_fingerprint.clone(),
            });
        }
        None => {
            user_metadata.notification_key = Some(NotificationKey {
                key: actual_firebase_notification_key,
                registration_tokens: vec![DeviceRegistrationToken {
                    token: registration_token.token.clone(),
                    device_fingerprint: registration_token.device_fingerprint.clone(),
                }],
            });
        }
    }

    let meta_raw_updated = serde_json::to_vec(&user_metadata).map_err(Error::Deser)?;
    conn.hset(user.clone(), METADATA_FIELD, &meta_raw_updated).await?;

    log::info!("[register_device] Device registered successfully for user {}.", user);

    Ok(Json(Ok(())))
}

#[web::delete("/notifications/{user_principal}")]
async fn unregister_device(
    state: State<AppState>,
    user_principal: Path<Principal>,
    req: Json<UnregisterDeviceReq>,
) -> Result<Json<ApiResult<UnregisterDeviceRes>>> {
    // Verify the identity of the sender
    let signature = req.0.signature;
    let registration_token = req.0.registration_token;
    signature.verify_identity(
        *user_principal.as_ref(),
        registration_token
            .clone()
            .try_into()
            .map_err(|_| Error::AuthTokenMissing)?,
    )?;

    // Get the user metadata
    let mut conn = state.redis.get().await?;
    let user = user_principal.to_text();
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
    let Some(meta_raw) = meta_raw else {
        return Ok(Json(Err(ApiError::MetadataNotFound)));
    };
    let mut user_metadata: UserMetadata =
        serde_json::from_slice(&meta_raw).map_err(Error::Deser)?;

    // Unregister the device with Firebase
    let notification_key_name =
        firebase::notifications::utils::get_notification_key_name_from_principal(&user);

    let Some(notification_key) = &user_metadata.notification_key else {
        return Ok(Json(Err(ApiError::NotificationKeyNotFound)));
    };

    let Some(token_to_delete) = notification_key
        .registration_tokens
        .iter()
        .filter(|token| {
            token.token == registration_token.token
                || token.device_fingerprint == registration_token.device_fingerprint
        })
        .map(|token| token.token.clone())
        .next()
    else {
        return Ok(Json(Err(ApiError::DeviceNotFound)));
    };

    let data = firebase::notifications::utils::get_remove_request_body(
        notification_key_name,
        notification_key.key.clone(),
        token_to_delete,
    )?;

    state.firebase.update_notification_devices(data).await?;

    if let Some(notification_key) = user_metadata.notification_key.as_mut() {
        notification_key.registration_tokens.retain(|token| {
            token.token != registration_token.token
                || token.device_fingerprint != registration_token.device_fingerprint
        });

        if notification_key.registration_tokens.is_empty() {
            user_metadata.notification_key = None;
        }

        let meta_raw = serde_json::to_vec(&user_metadata).map_err(Error::Deser)?;
        let _replaced: bool = conn.hset(user, METADATA_FIELD, &meta_raw).await?;

        log::info!("Device unregistered successfully");

        return Ok(Json(Ok(())));
    }

    Ok(Json(Err(ApiError::NotificationKeyNotFound)))
}

#[web::post("/notifications/{user_principal}/send")]
async fn send_notification(
    http_req: HttpRequest,
    state: State<AppState>,
    user_principal: Path<Principal>,
    req: Json<SendNotificationReq>,
) -> Result<Json<ApiResult<SendNotificationRes>>> {
    log::info!("[send_notification] Entered for user: {}", user_principal.as_ref().to_text());

    // --- Authentication Check ---
    let expected_api_key = env::var("YRAL_METADATA_USER_NOTIFICATION_API_KEY")
        .map_err(|_| Error::EnvironmentVariableMissing("YRAL_METADATA_USER_NOTIFICATION_API_KEY not set".to_string()))?;

    let auth_header = http_req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let provided_token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => {
            log::warn!("[send_notification] Authorization header missing or malformed for user: {}", user_principal.as_ref().to_text());
            return Ok(Json(Err(ApiError::Unauthorized))); // Or Missing Authorization Header
        }
    };

    if provided_token != expected_api_key {
        log::warn!("[send_notification] Invalid API key provided for user: {}", user_principal.as_ref().to_text());
        return Ok(Json(Err(ApiError::Unauthorized))); // Invalid Token
    }
    log::info!("[send_notification] Authentication successful for user: {}", user_principal.as_ref().to_text());
    // --- End Authentication Check ---

    let mut conn = state.redis.get().await?;
    let user = user_principal.to_text();
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
    let Some(meta_raw) = meta_raw else {
        log::warn!("[send_notification] Metadata not found for user: {}", user);
        return Ok(Json(Err(ApiError::MetadataNotFound)));
    };
    log::info!("[send_notification] Metadata found for user: {}", user);

    let user_metadata: UserMetadata = serde_json::from_slice(&meta_raw).map_err(Error::Deser)?;

    let Some(notification_key) = user_metadata.notification_key else {
        log::warn!("[send_notification] Notification key not found for user: {}", user);
        return Ok(Json(Err(ApiError::NotificationKeyNotFound)));
    };
    log::info!("[send_notification] Notification key found for user: {}: {}", user, notification_key.key);

    let data = req.0.data;
    log::info!("[send_notification] Preparing to send data for user {}: {:?}", user, data);

    log::info!("[send_notification] Calling send_message_to_group for user: {}", user);
    state
        .firebase
        .send_message_to_group(notification_key, data)
        .await?;
    log::info!("[send_notification] Successfully sent/processed notification for user: {}", user);
    Ok(Json(Ok(())))
}
