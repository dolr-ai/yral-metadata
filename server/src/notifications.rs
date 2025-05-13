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
    let registration_token_payload = req.0.registration_token.clone(); // Clone for use later
    
    // Clone user_principal for potential use in new metadata, before it's consumed or borrowed by signature verification
    let principal_for_new_metadata = user_principal.as_ref().clone();

    signature.verify_identity(
        *user_principal.as_ref(),
        Message::try_from(registration_token_payload.clone())?,
    )?;

    let mut conn = state.redis.get().await?;
    let user = user_principal.to_text(); // user is String representation of principal
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
    
    let mut user_metadata: UserMetadata = match meta_raw {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(Error::Deser)?,
        None => {
            log::info!("[register_device] No existing metadata for user {}. Creating new default metadata.", user);
            UserMetadata { 
                notification_key: None, 
                user_canister_id: principal_for_new_metadata, // This is Principal
                user_name: user.clone(),        // This is String (textual representation of principal)
            }
        }
    };

    let notification_key_name =
        firebase::notifications::utils::get_notification_key_name_from_principal(&user);

    // Determine operation data (create or add body) based on local metadata and FCM state
    let operation_data_result: Result<String> = {
        if let Some(existing_nk_obj) = user_metadata.notification_key.as_ref() {
            // Metadata has a key: try to ADD after potential REMOVE of old token for same device
            log::info!("[register_device] Found existing notification key in metadata for {}: {}. Preparing ADD.", user, existing_nk_obj.key);

            if let Some(old_device_token_to_remove) = existing_nk_obj
                .registration_tokens
                .iter()
                .find(|rt| rt.device_fingerprint == registration_token_payload.device_fingerprint)
                .map(|rt| rt.token.clone())
            {
                log::info!("[register_device] Found existing token for same device fingerprint ({}) for user {}. Attempting to remove it first.", registration_token_payload.device_fingerprint, user);
                let remove_data = firebase::notifications::utils::get_remove_request_body(
                    notification_key_name.clone(),
                    existing_nk_obj.key.clone(),
                    old_device_token_to_remove,
                )?;
                match state.firebase.update_notification_devices(remove_data).await {
                    Ok(_) => log::info!("[register_device] Successfully removed old device token for user {}.", user),
                    Err(e) => log::warn!("[register_device] Failed to remove old device token for user {}: {:?}. Proceeding with ADD.", user, e),
                }
            }
            
            firebase::notifications::utils::get_add_request_body(
                notification_key_name.clone(),
                existing_nk_obj.key.clone(), 
                registration_token_payload.token.clone(),
            )
        } else {
            // Metadata does NOT have a key. Check FCM directly.
            log::info!("[register_device] No notification key in metadata for user {}. Checking FCM for key name: {}", user, notification_key_name);
            match state.firebase.get_notification_key(&notification_key_name).await {
                Ok(Some(fcm_key_str)) => {
                    log::info!("[register_device] Metadata empty, but FCM has key for {}: {}. Using ADD.", user, fcm_key_str);
                    firebase::notifications::utils::get_add_request_body(
                        notification_key_name.clone(),
                        fcm_key_str, 
                        registration_token_payload.token.clone(),
                    )
                }
                Ok(None) => {
                    log::info!("[register_device] Metadata empty, and FCM has no key for user {}. Using CREATE.", user);
                    firebase::notifications::utils::get_create_request_body(
                        notification_key_name.clone(),
                        registration_token_payload.token.clone(),
                    )
                }
                Err(e) => {
                    log::error!("[register_device] Error checking FCM for existing key for user {}: {:?}", user, e);
                    Err(e) 
                }
            }
        }
    };

    let operation_data = operation_data_result?;

    let fcm_returned_notification_key = state
        .firebase
        .update_notification_devices(operation_data)
        .await?
        .ok_or_else(|| Error::Unknown( 
            format!("[register_device] FCM operation for user {} (key_name: {}) did not return a notification key.", user, notification_key_name)
        ))?;
    
    // Update or set user_metadata.notification_key
    match user_metadata.notification_key.as_mut() {
        Some(nk_meta) => {
            log::info!("[register_device] Updating existing metadata for user {}. Old key: {}, New key from FCM: {}", user, nk_meta.key, fcm_returned_notification_key);
            nk_meta.key = fcm_returned_notification_key;
            nk_meta.registration_tokens.retain(|rt| rt.device_fingerprint != registration_token_payload.device_fingerprint);
            nk_meta.registration_tokens.push(registration_token_payload);
        }
        None => {
            log::info!("[register_device] Setting new notification key in metadata for user {}. Key from FCM: {}", user, fcm_returned_notification_key);
            user_metadata.notification_key = Some(NotificationKey {
                key: fcm_returned_notification_key,
                registration_tokens: vec![registration_token_payload],
            });
        }
    }
    // user_canister_id and user_name are set if metadata was new. If metadata existed, they retain their old values
    // unless another mechanism updates them. This endpoint primarily focuses on notification setup.

    let meta_raw_updated = serde_json::to_vec(&user_metadata).map_err(Error::Deser)?;
    conn.hset(user, METADATA_FIELD, &meta_raw_updated).await?;

    log::info!("[register_device] Device registered successfully for user {}", user_principal.to_text());

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
