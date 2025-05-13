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
    let Some(meta_raw) = meta_raw else {
        return Ok(Json(Err(ApiError::MetadataNotFound)));
    };
    let mut user_metadata: UserMetadata =
        serde_json::from_slice(&meta_raw).map_err(Error::Deser)?;

    let notification_key_name =
        firebase::notifications::utils::get_notification_key_name_from_principal(&user);

    let data = match user_metadata.notification_key.as_ref() {
        Some(notification_key) => {
            let old_registration_token = notification_key
                .registration_tokens
                .iter()
                .find(|token| token.device_fingerprint == registration_token.device_fingerprint)
                .map(|token| token.token.clone());

            if let Some(old_registration_token) = old_registration_token {
                let data = firebase::notifications::utils::get_remove_request_body(
                    notification_key_name.clone(),
                    notification_key.key.clone(),
                    old_registration_token,
                )?;

                state.firebase.update_notification_devices(data).await?;
            }

            firebase::notifications::utils::get_add_request_body(
                notification_key_name,
                notification_key.key.clone(),
                registration_token.token.clone(),
            )
        }
        None => firebase::notifications::utils::get_create_request_body(
            notification_key_name,
            registration_token.token.clone(),
        ),
    };

    let notification_key = state
        .firebase
        .update_notification_devices(data?)
        .await?
        .ok_or(Error::Unknown(
            "create/add notification key did not return a notification key".to_string(),
        ))?;
    match user_metadata.notification_key.as_mut() {
        Some(meta) => {
            meta.registration_tokens
                .retain(|token| token.device_fingerprint != registration_token.device_fingerprint);

            meta.registration_tokens.push(DeviceRegistrationToken {
                token: registration_token.token.clone(),
                device_fingerprint: registration_token.device_fingerprint.clone(),
            });
        }
        None => {
            user_metadata.notification_key = Some(NotificationKey {
                key: notification_key,
                registration_tokens: vec![DeviceRegistrationToken {
                    token: registration_token.token.clone(),
                    device_fingerprint: registration_token.device_fingerprint.clone(),
                }],
            });
        }
    }

    let meta_raw = serde_json::to_vec(&user_metadata).map_err(Error::Deser)?;
    let _replaced: bool = conn.hset(user, METADATA_FIELD, &meta_raw).await?;

    log::info!("Device registered successfully");

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
