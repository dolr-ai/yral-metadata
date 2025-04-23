use candid::Principal;
use ntex::web::{
    self,
    types::{Json, Path, State},
};
use redis::AsyncCommands;
use types::{
    error::ApiError, ApiResult, DeviceRegistrationToken, NotificationKey, RegisterDeviceReq,
    RegisterDeviceRes, UnregisterDeviceReq, UnregisterDeviceRes, UserMetadata,
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

            if old_registration_token.is_some() {
                return Ok(Json(Err(ApiError::DeviceAlreadyRegistered)));
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

        let meta_raw = serde_json::to_vec(&user_metadata).map_err(Error::Deser)?;
        let _replaced: bool = conn.hset(user, METADATA_FIELD, &meta_raw).await?;

        log::info!("Device registered successfully");

        return Ok(Json(Ok(())));
    }

    Ok(Json(Err(ApiError::NotificationKeyNotFound)))
}
