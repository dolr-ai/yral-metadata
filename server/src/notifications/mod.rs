use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use candid::Principal;
use std::{env, sync::Arc};
use types::{
    error::ApiError, ApiResult, NotificationKey, RegisterDeviceReq, RegisterDeviceRes,
    SendNotificationReq, SendNotificationRes, UnregisterDeviceReq, UnregisterDeviceRes,
    UserMetadata,
};

#[cfg(test)]
mod mocks;
#[cfg(test)]
mod tests;
mod trait_impls;
pub mod traits;

use crate::{
    api::METADATA_FIELD,
    services::error_wrappers::{ErrorWrapper, OkWrapper},
    state::AppState,
    utils::error::{Error, Result},
};

use crate::firebase::notifications::utils as firebase_utils;
use crate::notifications::traits::{
    FcmService, RedisConnection, RegisterDeviceRequest, UnregisterDeviceRequest, UserPrincipal,
};

#[utoipa::path(
    post,
    path = "/notifications/{user_principal}",
    params(
        ("user_principal" = String, Path, description = "User principal ID")
    ),
    request_body = RegisterDeviceReq,
    responses(
        (status = 200, description = "Register device successfully", body = OkWrapper<RegisterDeviceRes>),
        (status = 400, description = "Invalid request", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 401, description = "Unauthorized", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 404, description = "User metadata not found", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<crate::utils::error::Error>)
    )
)]
pub async fn register_device(
    State(state): State<Arc<AppState>>,
    Path(user_principal): Path<Principal>,
    Json(req): Json<RegisterDeviceReq>,
) -> Result<Json<ApiResult<RegisterDeviceRes>>> {
    let principal = user_principal;

    crate::sentry_utils::add_user_context(principal, None);
    crate::sentry_utils::add_operation_breadcrumb(
        "notifications",
        &format!("Registering device for user: {}", principal),
        sentry::Level::Info,
    );

    let mut redis_conn_pooled = state.redis.get().await.map_err(Error::Bb8)?;
    let redis_service = &mut *redis_conn_pooled;
    let firebase_service = &state.firebase;

    register_device_impl(
        firebase_service,
        redis_service,
        user_principal,
        Json(req),
    )
    .await
    .map_err(|e| {
        crate::sentry_utils::capture_api_error(
            &e,
            "/notifications/{user_principal}",
            Some(&principal.to_text()),
        );
        e
    })
}

pub async fn register_device_impl<
    F: FcmService,
    R: RedisConnection,
    P: UserPrincipal,
    Req: RegisterDeviceRequest,
>(
    fcm_service: &F,
    redis_service: &mut R,
    user_principal: P,
    req: Json<Req>,
) -> Result<Json<ApiResult<RegisterDeviceRes>>> {
    let request_data = req.0;
    let registration_token_obj = request_data.registration_token();

    request_data.verify_identity_against_principal(&user_principal)?;

    let user_id_text = user_principal.to_text();

    let mut user_metadata: UserMetadata = {
        let meta_raw: Option<Vec<u8>> = redis_service
            .hget(&user_id_text, METADATA_FIELD)
            .await
            .map_err(Error::Redis)?;
        match meta_raw {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(Error::Deser)?,
            None => return Ok(Json(Err(ApiError::MetadataNotFound))),
        }
    };

    if !user_metadata.is_migrated {
        user_metadata.notification_key = None;
        user_metadata.is_migrated = true;
    }

    let maybe_notification_key_ref = user_metadata.notification_key.as_ref();
    let original_key_in_redis: Option<String> = maybe_notification_key_ref.map(|nk| nk.key.clone());

    let notification_key_name =
        firebase_utils::get_notification_key_name_from_principal(&user_id_text);

    let (fcm_request_body_json, is_create_operation) = match maybe_notification_key_ref {
        Some(notification_key) => {
            let old_reg_token_opt = notification_key
                .registration_tokens
                .iter()
                .find(|token| token.token == registration_token_obj.token)
                .map(|token| token.token.clone());

            if let Some(old_token_to_remove) = old_reg_token_opt {
                let remove_body_str = firebase_utils::get_remove_request_body(
                    notification_key_name.clone(),
                    notification_key.key.clone(),
                    old_token_to_remove,
                );
                let remove_body_json: serde_json::Value = serde_json::to_value(&remove_body_str)
                    .map_err(|e| {
                        Error::Unknown(format!("Failed to parse remove_body to JSON: {}", e))
                    })?;
                fcm_service
                    .update_notification_devices(remove_body_json)
                    .await?;
            }

            let add_body_str = firebase_utils::get_add_request_body(
                notification_key_name.clone(),
                notification_key.key.clone(),
                registration_token_obj.token.clone(),
            );
            let add_body_json: serde_json::Value = serde_json::to_value(&add_body_str)
                .map_err(|e| Error::Unknown(format!("Failed to parse add_body to JSON: {}", e)))?;
            (add_body_json, false)
        }
        None => {
            let create_body_str = firebase_utils::get_create_request_body(
                notification_key_name.clone(),
                registration_token_obj.token.clone(),
            );
            let create_body_json: serde_json::Value = serde_json::to_value(&create_body_str)
                .map_err(|e| {
                    Error::Unknown(format!("Failed to parse create_body to JSON: {}", e))
                })?;
            (create_body_json, true)
        }
    };

    let notification_key_from_firebase = if !is_create_operation {
        match fcm_service
            .update_notification_devices(fcm_request_body_json)
            .await
        {
            Ok(Some(key)) => {
                crate::sentry_utils::add_firebase_breadcrumb(
                    "update_notification_devices",
                    &user_id_text,
                    true,
                );
                key
            }
            Err(Error::FirebaseApiErr(err_text)) if err_text.contains("not found") => {
                crate::sentry_utils::add_firebase_breadcrumb(
                    "update_notification_devices",
                    &user_id_text,
                    false,
                );
                log::warn!(
                    "Attempted to add device to notification_key_name '{}' which was not found in FCM. Attempting to create.",
                    notification_key_name
                );
                let create_body_str = firebase_utils::get_create_request_body(
                    notification_key_name.clone(),
                    registration_token_obj.token.clone(),
                );
                let create_body_json: serde_json::Value = serde_json::to_value(&create_body_str)
                    .map_err(|e| {
                        Error::Unknown(format!(
                            "Failed to parse create_body for retry to JSON: {}",
                            e
                        ))
                    })?;
                fcm_service
                    .update_notification_devices(create_body_json)
                    .await?
                    .ok_or_else(|| {
                        Error::Unknown(
                            "create notification key (after add to non-existent key failed) did not return a notification key"
                                .to_string(),
                        )
                    })?
            }
            Err(e) => return Err(e),
            Ok(None) => {
                return Err(Error::Unknown(
                    "add/update notification key did not return a notification key".to_string(),
                ))
            }
        }
    } else {
        match fcm_service
            .update_notification_devices(fcm_request_body_json.clone())
            .await
        {
            Ok(Some(key)) => key,
            Err(Error::FirebaseApiErr(err_text))
                if err_text.contains("notification_key_name exists")
                    || err_text.contains("notification_key") =>
            {
                let v: serde_json::Value = serde_json::from_str(&err_text).map_err(|_| {
                    Error::FirebaseApiErr(format!(
                        "Failed to parse FCM error for existing key: {}",
                        err_text
                    ))
                })?;
                let existing_key = v
                    .get("notification_key")
                    .and_then(|val| val.as_str())
                    .ok_or_else(|| {
                        Error::FirebaseApiErr(format!(
                            "FCM error (during create) missing notification_key: {}",
                            err_text
                        ))
                    })?
                    .to_string();

                let add_body_str = firebase_utils::get_add_request_body(
                    notification_key_name.clone(),
                    existing_key.clone(),
                    registration_token_obj.token.clone(),
                );
                let add_body_json: serde_json::Value = serde_json::to_value(&add_body_str)
                    .map_err(|e| {
                        Error::Unknown(format!(
                            "Failed to parse add_body for existing key to JSON: {}",
                            e
                        ))
                    })?;

                fcm_service
                    .update_notification_devices(add_body_json)
                    .await?
                    .ok_or_else(|| {
                        Error::Unknown(
                            "add notification token (after key_name exists) did not return a notification key"
                                .to_string(),
                        )
                    })?;
                existing_key
            }
            Err(e) => return Err(e),
            Ok(None) => {
                return Err(Error::Unknown(
                    "create notification key did not return a notification key".to_string(),
                ))
            }
        }
    };

    match user_metadata.notification_key.as_mut() {
        Some(meta) => {
            if is_create_operation
                || original_key_in_redis.as_ref() != Some(&notification_key_from_firebase)
            {
                meta.registration_tokens.clear();
            }
            meta.key = notification_key_from_firebase;
            meta.registration_tokens
                .retain(|token| token.token != registration_token_obj.token);
            meta.registration_tokens.push(registration_token_obj);
        }
        None => {
            user_metadata.notification_key = Some(NotificationKey {
                key: notification_key_from_firebase,
                registration_tokens: vec![registration_token_obj],
            });
        }
    }

    let meta_raw_to_save = serde_json::to_vec(&user_metadata).map_err(Error::Deser)?;
    redis_service
        .hset(&user_id_text, METADATA_FIELD, &meta_raw_to_save)
        .await
        .map_err(Error::Redis)?;

    log::info!("Device registered successfully for user: {}", user_id_text);

    Ok(Json(Ok(())))
}

#[utoipa::path(
    delete,
    path = "/notifications/{user_principal}",
    params(
        ("user_principal" = String, Path, description = "User principal ID")
    ),
    request_body = UnregisterDeviceReq,
    responses(
        (status = 200, description = "Unregister device successfully", body = OkWrapper<UnregisterDeviceRes>),
        (status = 400, description = "Invalid request", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 401, description = "Unauthorized", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 404, description = "User metadata or device not found", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<crate::utils::error::Error>)
    )
)]
pub async fn unregister_device(
    State(state): State<Arc<AppState>>,
    Path(user_principal): Path<Principal>,
    Json(req): Json<UnregisterDeviceReq>,
) -> Result<Json<ApiResult<UnregisterDeviceRes>>> {
    let mut redis_conn_pooled = state.redis.get().await.map_err(Error::Bb8)?;
    let redis_service = &mut *redis_conn_pooled;
    let firebase_service = &state.firebase;
    unregister_device_impl(
        firebase_service,
        redis_service,
        user_principal,
        Json(req),
    )
    .await
}

pub async fn unregister_device_impl<
    F: FcmService,
    R: RedisConnection,
    P: UserPrincipal,
    Req: UnregisterDeviceRequest,
>(
    fcm_service: &F,
    redis_service: &mut R,
    user_principal: P,
    req: Json<Req>,
) -> Result<Json<ApiResult<UnregisterDeviceRes>>> {
    let request_data = req.0;
    let registration_token_obj = request_data.registration_token();

    request_data.verify_identity_against_principal(&user_principal)?;

    let user_id_text = user_principal.to_text();

    let mut user_metadata: UserMetadata = {
        let meta_raw: Option<Vec<u8>> = redis_service
            .hget(&user_id_text, METADATA_FIELD)
            .await
            .map_err(Error::Redis)?;
        match meta_raw {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(Error::Deser)?,
            None => return Ok(Json(Err(ApiError::MetadataNotFound))),
        }
    };

    let notification_key_name =
        firebase_utils::get_notification_key_name_from_principal(&user_id_text);

    let Some(user_notification_key_info) = &user_metadata.notification_key else {
        return Ok(Json(Err(ApiError::NotificationKeyNotFound)));
    };

    let Some(token_to_delete_str) = user_notification_key_info
        .registration_tokens
        .iter()
        .find(|token| token.token == registration_token_obj.token)
        .map(|token| token.token.clone())
    else {
        return Ok(Json(Err(ApiError::DeviceNotFound)));
    };

    let fcm_remove_body_str = firebase_utils::get_remove_request_body(
        notification_key_name.clone(),
        user_notification_key_info.key.clone(),
        token_to_delete_str.clone(),
    );
    let fcm_remove_body_json: serde_json::Value = serde_json::to_value(&fcm_remove_body_str)
        .map_err(|e| {
            Error::Unknown(format!(
                "Failed to parse remove_body for unregister to JSON: {}",
                e
            ))
        })?;

    match fcm_service
        .update_notification_devices(fcm_remove_body_json)
        .await
    {
        Ok(_) => {
            log::info!(
                "Successfully processed remove token from FCM for user {} or token was already absent from FCM group: {}",
                user_id_text, registration_token_obj.token
            );
        }
        Err(Error::FirebaseApiErr(err_text)) if err_text.contains("not found") => {
            log::warn!(
                "Attempted to remove device from notification_key_name '{}' which was not found in FCM (or token not in group). Proceeding with Redis cleanup. Error: {}",
                notification_key_name,
                err_text
            );
        }
        Err(e) => return Err(e),
    }

    if let Some(nk_meta) = user_metadata.notification_key.as_mut() {
        nk_meta
            .registration_tokens
            .retain(|token| token.token != registration_token_obj.token);

        let meta_raw_to_save = serde_json::to_vec(&user_metadata).map_err(Error::Deser)?;
        redis_service
            .hset(&user_id_text, METADATA_FIELD, &meta_raw_to_save)
            .await
            .map_err(Error::Redis)?;

        log::info!(
            "Device unregistered successfully in Redis for user: {}",
            user_id_text
        );
        return Ok(Json(Ok(())));
    } else {
        log::warn!(
            "Notification key became None unexpectedly during unregister for user: {}",
            user_id_text
        );
        Ok(Json(Err(ApiError::NotificationKeyNotFound)))
    }
}

#[utoipa::path(
    post,
    path = "/notifications/{user_principal}/send",
    params(
        ("user_principal" = String, Path, description = "User principal ID")
    ),
    request_body = SendNotificationReq,
    responses(
        (status = 200, description = "Send notification successfully", body = OkWrapper<SendNotificationRes>),
        (status = 400, description = "Invalid request", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 401, description = "Unauthorized", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 404, description = "User metadata or notification key not found", body = ErrorWrapper<crate::utils::error::Error>),
        (status = 500, description = "Internal server error", body = ErrorWrapper<crate::utils::error::Error>)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
pub async fn send_notification(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Path(user_principal): Path<Principal>,
    Json(req): Json<SendNotificationReq>,
) -> Result<Json<ApiResult<SendNotificationRes>>> {
    let principal = user_principal;

    crate::sentry_utils::add_user_context(principal, None);
    crate::sentry_utils::add_operation_breadcrumb(
        "notifications",
        &format!("Sending notification to user: {}", principal),
        sentry::Level::Info,
    );

    let mut redis_conn_pooled = state.redis.get().await.map_err(Error::Bb8)?;
    let redis_service = &mut *redis_conn_pooled;
    let firebase_service = &state.firebase;

    send_notification_impl(
        Some(&headers),
        firebase_service,
        redis_service,
        user_principal,
        Json(req),
    )
    .await
    .map_err(|e| {
        crate::sentry_utils::capture_api_error(
            &e,
            "/notifications/{user_principal}/send",
            Some(&principal.to_text()),
        );
        e
    })
}

pub async fn send_notification_impl<F: FcmService, R: RedisConnection, P: UserPrincipal>(
    headers: Option<&HeaderMap>,
    fcm_service: &F,
    redis_service: &mut R,
    user_principal: P,
    req: Json<SendNotificationReq>,
) -> Result<Json<ApiResult<SendNotificationRes>>> {
    let user_id_text = user_principal.to_text();

    if let Some(actual_headers) = headers {
        log::info!("[send_notification] Entered for user: {}", user_id_text);
        let expected_api_key =
            env::var("YRAL_METADATA_USER_NOTIFICATION_API_KEY").map_err(|_| {
                Error::EnvironmentVariableMissing(
                    "YRAL_METADATA_USER_NOTIFICATION_API_KEY not set".to_string(),
                )
            })?;

        let auth_header = actual_headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok());

        let provided_token = match auth_header {
            Some(header) if header.starts_with("Bearer ") => &header[7..],
            _ => {
                log::warn!(
                    "[send_notification] Authorization header missing or malformed for user: {}",
                    user_id_text
                );
                return Ok(Json(Err(ApiError::Unauthorized)));
            }
        };

        if provided_token != expected_api_key {
            log::warn!(
                "[send_notification] Invalid API key provided for user: {}",
                user_id_text
            );
            return Ok(Json(Err(ApiError::Unauthorized)));
        }
        log::info!(
            "[send_notification] Authentication successful for user: {}",
            user_id_text
        );
    }

    let user_metadata: UserMetadata = {
        let meta_raw: Option<Vec<u8>> = redis_service
            .hget(&user_id_text, METADATA_FIELD)
            .await
            .map_err(Error::Redis)?;
        match meta_raw {
            Some(bytes) => serde_json::from_slice(&bytes).map_err(Error::Deser)?,
            None => return Ok(Json(Err(ApiError::MetadataNotFound))),
        }
    };

    let Some(notification_key_to_use) = user_metadata.notification_key else {
        log::warn!(
            "[send_notification] Notification key not found for user: {}",
            user_id_text
        );
        return Ok(Json(Err(ApiError::NotificationKeyNotFound)));
    };
    log::info!(
        "[send_notification] Notification key found for user: {}: {}",
        user_id_text,
        notification_key_to_use.key
    );

    let data_to_send = req.0;
    log::info!(
        "[send_notification] Preparing to send data for user {}: {:?}",
        user_id_text,
        data_to_send
    );

    log::info!(
        "[send_notification] Calling send_message_to_group for user: {}",
        user_id_text
    );
    fcm_service
        .send_message_to_group(notification_key_to_use, data_to_send)
        .await?;

    log::info!(
        "[send_notification] Successfully sent/processed notification for user: {}",
        user_id_text
    );
    Ok(Json(Ok(())))
}
