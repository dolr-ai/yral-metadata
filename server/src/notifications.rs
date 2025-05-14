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
    let registration_token_req = req.0.registration_token; // Renamed to avoid conflict
    signature.verify_identity(
        *user_principal.as_ref(),
        Message::try_from(registration_token_req.clone())?,
    )?;

    let mut conn = state.redis.get().await?;
    let user = user_principal.to_text();
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
    
    let mut user_metadata: UserMetadata = match meta_raw {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(Error::Deser)?,
        None => UserMetadata { user_canister_id: user_principal.into_inner(), user_name: String::new(), notification_key: None },
    };

    let notification_key_name =
        firebase::notifications::utils::get_notification_key_name_from_principal(&user);

    let mut perform_create = false;
    let mut new_notification_key_data: Option<NotificationKey> = None;

    if let Some(current_nk_meta) = user_metadata.notification_key.as_ref() {
        let mut key_from_metadata = current_nk_meta.key.clone();
        let mut current_tokens_in_meta = current_nk_meta.registration_tokens.clone();
        let mut force_create_due_to_remove_issue = false;

        // Check if this device fingerprint is already registered to remove the old token
        if let Some(pos) = current_tokens_in_meta.iter().position(|token| token.device_fingerprint == registration_token_req.device_fingerprint) {
            let old_token_string = current_tokens_in_meta[pos].token.clone();
            let is_last_token_in_group = current_tokens_in_meta.len() == 1;

            log::info!("Attempting to remove old token for device fingerprint: {}", registration_token_req.device_fingerprint);
            let remove_req_body = firebase::notifications::utils::get_remove_request_body(
                notification_key_name.clone(),
                key_from_metadata.clone(),
                old_token_string,
            )?;
            
            match state.firebase.update_notification_devices(remove_req_body).await {
                Ok(None) => { // Successful remove from FCM
                    log::info!("Successfully removed old token from FCM for device fingerprint: {}", registration_token_req.device_fingerprint);
                    current_tokens_in_meta.remove(pos);
                    if is_last_token_in_group {
                        log::info!("Removed the last token; FCM group likely deleted. Forcing create for new registration.");
                        force_create_due_to_remove_issue = true;
                    }
                    // If not the last token, key_from_metadata *should* still be valid for subsequent add.
                    // FCM docs say remove op can return a new key, but our impl discards it.
                    // This is fine as long as the key wasn't for a group that just got deleted.
                }
                Ok(Some(_)) => { /* This case is not expected from current update_notification_devices for remove */ 
                    log::warn!("FCM remove operation unexpectedly returned a notification key.");
                }
                Err(Error::FirebaseApiErr(msg)) if msg.contains("notification_key not found") => {
                    log::warn!("FCM reported notification_key not found during pre-emptive remove of old token. Forcing create.");
                    force_create_due_to_remove_issue = true; // Key was already bad
                }
                Err(e) => {
                    log::error!("Error removing old token from FCM: {:?}", e);
                    return Err(e); // Propagate other critical errors
                }
            }
        }

        if force_create_due_to_remove_issue {
            perform_create = true;
        } else {
            // Attempt to ADD the new token
            log::info!("Attempting to add new token to existing FCM group.");
            let add_req_body = firebase::notifications::utils::get_add_request_body(
                notification_key_name.clone(),
                key_from_metadata.clone(), // Use the key we believe is current
                registration_token_req.token.clone(),
            )?;
            match state.firebase.update_notification_devices(add_req_body).await {
                Ok(Some(key_from_fcm_add)) => {
                    log::info!("Successfully added token to existing FCM group. New/updated key: {}", key_from_fcm_add);
                    // Update tokens list: remove any old one by fingerprint, then add new one
                    current_tokens_in_meta.retain(|t| t.device_fingerprint != registration_token_req.device_fingerprint);
                    current_tokens_in_meta.push(registration_token_req.clone());
                    new_notification_key_data = Some(NotificationKey {
                        key: key_from_fcm_add,
                        registration_tokens: current_tokens_in_meta,
                    });
                }
                Ok(None) => {
                    log::error!("FCM Add operation did not return a notification key as expected.");
                    // This is an unexpected state, perhaps fallback to create or error out.
                    // Forcing create as a recovery mechanism.
                    perform_create = true; 
                }
                Err(Error::FirebaseApiErr(msg)) if msg.contains("notification_key not found") => {
                    log::warn!("FCM Add operation failed (notification_key not found). Switching to create new group.");
                    perform_create = true;
                }
                Err(e) => {
                    log::error!("Error adding token to FCM group: {:?}", e);
                    return Err(e); // Propagate other critical errors
                }
            }
        }
    } else { // user_metadata.notification_key was None initially
        log::info!("No existing notification key in metadata. Proceeding to create new group.");
        perform_create = true;
    }

    if perform_create {
        log::info!("Performing create operation for new FCM notification group.");
        let create_req_body = firebase::notifications::utils::get_create_request_body(
            notification_key_name.clone(),
            registration_token_req.token.clone(),
        )?;
        match state.firebase.update_notification_devices(create_req_body).await {
            Ok(Some(key_from_fcm_create)) => {
                log::info!("Successfully created new FCM notification group. Key: {}", key_from_fcm_create);
                new_notification_key_data = Some(NotificationKey {
                    key: key_from_fcm_create,
                    registration_tokens: vec![registration_token_req.clone()],
                });
            }
            Ok(None) => {
                 log::error!("FCM Create operation did not return a notification key as expected.");
                 return Err(Error::Unknown("FCM Create op did not return key".to_string()));
            }
            Err(e) => {
                log::error!("Error creating new FCM notification group: {:?}", e);
                return Err(e); // Propagate critical error
            }
        }
    }

    // Update metadata in Redis
    if let Some(nk_data) = new_notification_key_data {
        user_metadata.notification_key = Some(nk_data);
    } else if perform_create {
        // This case should ideally not be reached if create was successful and returned a key.
        // If create failed and returned Err, we would have exited.
        // If create returned Ok(None), we would have errored.
        // This implies perform_create was true, but new_notification_key_data wasn't set, which is an anomaly.
        log::error!("Logic anomaly: perform_create was true but no new_notification_key_data was set.");
        return Err(Error::Unknown("Failed to obtain notification key from FCM after create attempt.".to_string()));
    }
    // If !perform_create and new_notification_key_data is None, it means the add op failed in a way that didn't set perform_create.
    // This shouldn't happen with the current logic (add either succeeds, sets perform_create, or errors out).
    // However, user_metadata.notification_key might have been updated in place if the 'if let Some(current_nk_meta)' path was taken and successful without 'perform_create'.
    // The current structure ensures new_notification_key_data is set if any FCM op succeeds in setting/updating a key.


    let meta_raw_updated = serde_json::to_vec(&user_metadata).map_err(Error::Deser)?;
    let _replaced: bool = conn.hset(user, METADATA_FIELD, &meta_raw_updated).await?;

    log::info!("Device registered successfully (end of register_device logic).");
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
