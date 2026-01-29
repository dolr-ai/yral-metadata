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
    dragonfly::{format_to_dragonfly_key, YRAL_METADATA_KEY_PREFIX},
    services::error_wrappers::{ErrorWrapper, OkWrapper},
    state::AppState,
    utils::error::{Error, Result},
};

use crate::firebase::notifications::utils as firebase_utils;
use crate::notifications::traits::{
    FcmService, RedisConnection, RegisterDeviceRequest, UnregisterDeviceRequest, UserPrincipal,
};
use serde::Serialize;
use types::DeviceRegistrationToken;

/// Fetches user metadata from Dragonfly/Redis
async fn fetch_user_metadata<D: RedisConnection>(
    dragonfly_service: &mut D,
    key_prefix: &str,
    user_id_text: &str,
) -> Result<UserMetadata> {
    let meta_raw: Option<Vec<u8>> = dragonfly_service
        .hget(
            &format_to_dragonfly_key(key_prefix, user_id_text),
            METADATA_FIELD,
        )
        .await
        .map_err(Error::Redis)?;

    match meta_raw {
        Some(bytes) => serde_json::from_slice(&bytes).map_err(Error::Deser),
        None => Err(Error::Unknown("User metadata not found".to_string())),
    }
}

/// Saves user metadata to Dragonfly/Redis
async fn save_user_metadata<D: RedisConnection>(
    dragonfly_service: &mut D,
    key_prefix: &str,
    user_id_text: &str,
    user_metadata: &UserMetadata,
) -> Result<()> {
    let meta_raw = serde_json::to_vec(user_metadata).map_err(Error::Deser)?;
    dragonfly_service
        .hset(
            &format_to_dragonfly_key(key_prefix, user_id_text),
            METADATA_FIELD,
            &meta_raw,
        )
        .await
        .map_err(Error::Redis)?;
    Ok(())
}

/// Serializes FCM request body to JSON
fn serialize_fcm_request<T: Serialize>(request: &T) -> Result<serde_json::Value> {
    serde_json::to_value(request)
        .map_err(|e| Error::Unknown(format!("Failed to serialize FCM request: {}", e)))
}

/// Updates notification key metadata with new registration token
fn update_notification_key_metadata(
    user_metadata: &mut UserMetadata,
    notification_key_from_firebase: String,
    registration_token: DeviceRegistrationToken,
    is_create_operation: bool,
    original_key: Option<&String>,
) {
    match user_metadata.notification_key.as_mut() {
        Some(meta) => {
            // Clear tokens if key changed or is newly created
            if is_create_operation || Some(&notification_key_from_firebase) != original_key {
                meta.registration_tokens.clear();
            }
            meta.key = notification_key_from_firebase;
            // Remove duplicate token if exists, then add
            meta.registration_tokens
                .retain(|token| token.token != registration_token.token);
            meta.registration_tokens.push(registration_token);
        }
        None => {
            user_metadata.notification_key = Some(NotificationKey {
                key: notification_key_from_firebase,
                registration_tokens: vec![registration_token],
            });
        }
    }
}

/// Handles adding a device to an existing notification group
async fn add_device_to_existing_group<F: FcmService>(
    fcm_service: &F,
    notification_key_name: &str,
    existing_notification_key: &NotificationKey,
    new_token: &str,
) -> Result<Option<String>> {
    // Remove old token if it already exists in the group
    if existing_notification_key
        .registration_tokens
        .iter()
        .any(|t| t.token == new_token)
    {
        let remove_body = firebase_utils::get_remove_request_body(
            notification_key_name.to_string(),
            existing_notification_key.key.clone(),
            new_token.to_string(),
        );
        fcm_service
            .update_notification_devices(serialize_fcm_request(&remove_body)?)
            .await?;
    }

    // Add the new token to the group
    let add_body = firebase_utils::get_add_request_body(
        notification_key_name.to_string(),
        existing_notification_key.key.clone(),
        new_token.to_string(),
    );
    fcm_service
        .update_notification_devices(serialize_fcm_request(&add_body)?)
        .await
}

/// Creates a new notification group
async fn create_notification_group<F: FcmService>(
    fcm_service: &F,
    notification_key_name: &str,
    token: &str,
) -> Result<String> {
    let create_body =
        firebase_utils::get_create_request_body(notification_key_name.to_string(), token.to_string());
    fcm_service
        .update_notification_devices(serialize_fcm_request(&create_body)?)
        .await?
        .ok_or_else(|| Error::Unknown("FCM did not return a notification key after creation".to_string()))
}

/// Handles the case when trying to create a group that already exists
async fn handle_existing_group_error<F: FcmService>(
    fcm_service: &F,
    err_text: &str,
    notification_key_name: &str,
    token: &str,
) -> Result<String> {
    let error_json: serde_json::Value = serde_json::from_str(err_text).map_err(|_| {
        Error::FirebaseApiErr(format!(
            "Failed to parse FCM error for existing key: {}",
            err_text
        ))
    })?;

    let existing_key = error_json
        .get("notification_key")
        .and_then(|val| val.as_str())
        .ok_or_else(|| {
            Error::FirebaseApiErr(format!(
                "FCM error missing notification_key field: {}",
                err_text
            ))
        })?
        .to_string();

    // Add the token to the existing group
    let add_body = firebase_utils::get_add_request_body(
        notification_key_name.to_string(),
        existing_key.clone(),
        token.to_string(),
    );
    fcm_service
        .update_notification_devices(serialize_fcm_request(&add_body)?)
        .await?;

    Ok(existing_key)
}

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

    let mut dragonfly_conn_pooled = state.dragonfly_redis.get().await?;
    let dragonfly_service = &mut dragonfly_conn_pooled;
    let firebase_service = &state.firebase;

    register_device_impl(
        firebase_service,
        dragonfly_service,
        user_principal,
        Json(req),
        YRAL_METADATA_KEY_PREFIX,
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
    D: RedisConnection,
    P: UserPrincipal,
    Req: RegisterDeviceRequest,
>(
    fcm_service: &F,
    dragonfly_service: &mut D,
    user_principal: P,
    req: Json<Req>,
    key_prefix: &str,
) -> Result<Json<ApiResult<RegisterDeviceRes>>> {
    let request_data = req.0;
    let registration_token_obj = request_data.registration_token();

    request_data.verify_identity_against_principal(&user_principal)?;

    let user_id_text = user_principal.to_text();

    let mut user_metadata = match fetch_user_metadata(dragonfly_service, key_prefix, &user_id_text).await {
        Ok(metadata) => metadata,
        Err(_) => return Ok(Json(Err(ApiError::MetadataNotFound))),
    };

    // Clear notification key for unmigrated users
    if !user_metadata.is_migrated {
        user_metadata.notification_key = None;
        user_metadata.is_migrated = true;
    }

    let original_key = user_metadata.notification_key.as_ref().map(|nk| nk.key.clone());
    let notification_key_name = firebase_utils::get_notification_key_name_from_principal(&user_id_text);
    let token = registration_token_obj.token.clone();

    // Register device with FCM
    let (notification_key_from_firebase, is_create) = match &user_metadata.notification_key {
        Some(existing_key) => {
            // Try to add to existing group
            match add_device_to_existing_group(fcm_service, &notification_key_name, existing_key, &token).await {
                Ok(Some(key)) => {
                    crate::sentry_utils::add_firebase_breadcrumb(
                        "update_notification_devices",
                        &user_id_text,
                        true,
                    );
                    (key, false)
                }
                Err(Error::FirebaseApiErr(err_text)) if err_text.contains("not found") => {
                    // Group not found in FCM, create new one
                    crate::sentry_utils::add_firebase_breadcrumb(
                        "update_notification_devices",
                        &user_id_text,
                        false,
                    );
                    log::warn!(
                        "Notification group '{}' not found in FCM. Creating new group.",
                        notification_key_name
                    );
                    (create_notification_group(fcm_service, &notification_key_name, &token).await?, true)
                }
                Ok(None) => {
                    return Err(Error::Unknown(
                        "FCM did not return notification key after add operation".to_string(),
                    ))
                }
                Err(e) => return Err(e),
            }
        }
        None => {
            // Create new notification group
            match create_notification_group(fcm_service, &notification_key_name, &token).await {
                Ok(key) => (key, true),
                Err(Error::FirebaseApiErr(err_text))
                    if err_text.contains("notification_key_name exists")
                        || err_text.contains("notification_key") =>
                {
                    // Group already exists, add to it
                    (handle_existing_group_error(fcm_service, &err_text, &notification_key_name, &token).await?, false)
                }
                Err(e) => return Err(e),
            }
        }
    };

    // Update local metadata
    update_notification_key_metadata(
        &mut user_metadata,
        notification_key_from_firebase,
        registration_token_obj,
        is_create,
        original_key.as_ref(),
    );

    // Save to Redis
    save_user_metadata(dragonfly_service, key_prefix, &user_id_text, &user_metadata).await?;

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
    let mut dragonfly_conn_pooled = state.dragonfly_redis.get().await?;

    let dragonfly_service = &mut dragonfly_conn_pooled;
    let firebase_service = &state.firebase;
    unregister_device_impl(
        firebase_service,
        dragonfly_service,
        user_principal,
        Json(req),
        YRAL_METADATA_KEY_PREFIX,
    )
    .await
}

pub async fn unregister_device_impl<
    F: FcmService,
    D: RedisConnection,
    P: UserPrincipal,
    Req: UnregisterDeviceRequest,
>(
    fcm_service: &F,
    dragonfly_service: &mut D,
    user_principal: P,
    req: Json<Req>,
    key_prefix: &str,
) -> Result<Json<ApiResult<UnregisterDeviceRes>>> {
    let request_data = req.0;
    let registration_token_obj = request_data.registration_token();

    request_data.verify_identity_against_principal(&user_principal)?;

    let user_id_text = user_principal.to_text();

    let mut user_metadata = match fetch_user_metadata(dragonfly_service, key_prefix, &user_id_text).await {
        Ok(metadata) => metadata,
        Err(_) => return Ok(Json(Err(ApiError::MetadataNotFound))),
    };

    let notification_key_name =
        firebase_utils::get_notification_key_name_from_principal(&user_id_text);

    let Some(user_notification_key_info) = &user_metadata.notification_key else {
        return Ok(Json(Err(ApiError::NotificationKeyNotFound)));
    };

    // Check if token exists in metadata
    if !user_notification_key_info
        .registration_tokens
        .iter()
        .any(|token| token.token == registration_token_obj.token)
    {
        return Ok(Json(Err(ApiError::DeviceNotFound)));
    }

    // Remove from FCM
    let fcm_remove_body = firebase_utils::get_remove_request_body(
        notification_key_name.clone(),
        user_notification_key_info.key.clone(),
        registration_token_obj.token.clone(),
    );

    match fcm_service
        .update_notification_devices(serialize_fcm_request(&fcm_remove_body)?)
        .await
    {
        Ok(_) => {
            log::info!(
                "Removed device from FCM group for user {}: {}",
                user_id_text, registration_token_obj.token
            );
        }
        Err(Error::FirebaseApiErr(err_text)) if err_text.contains("not found") => {
            log::warn!(
                "Device group '{}' not found in FCM. Proceeding with Redis cleanup. Error: {}",
                notification_key_name,
                err_text
            );
        }
        Err(e) => return Err(e),
    }

    // Remove from Redis metadata
    if let Some(nk_meta) = user_metadata.notification_key.as_mut() {
        nk_meta
            .registration_tokens
            .retain(|token| token.token != registration_token_obj.token);

        save_user_metadata(dragonfly_service, key_prefix, &user_id_text, &user_metadata).await?;

        log::info!("Device unregistered successfully for user: {}", user_id_text);
        Ok(Json(Ok(())))
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

    let mut dragonfly_conn_pooled = state.dragonfly_redis.get().await?;

    let dragonfly_service = &mut dragonfly_conn_pooled;
    let firebase_service = &state.firebase;

    send_notification_impl(
        Some(&headers),
        firebase_service,
        dragonfly_service,
        user_principal,
        Json(req),
        YRAL_METADATA_KEY_PREFIX,
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

pub async fn send_notification_impl<F: FcmService, D: RedisConnection, P: UserPrincipal>(
    headers: Option<&HeaderMap>,
    fcm_service: &F,
    dragonfly_service: &mut D,
    user_principal: P,
    req: Json<SendNotificationReq>,
    key_prefix: &str,
) -> Result<Json<ApiResult<SendNotificationRes>>> {
    let user_id_text = user_principal.to_text();

    // Verify API key authorization if headers provided
    if let Some(actual_headers) = headers {
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
                log::warn!("Authorization header missing or malformed for user: {}", user_id_text);
                return Ok(Json(Err(ApiError::Unauthorized)));
            }
        };

        if provided_token != expected_api_key {
            log::warn!("Invalid API key provided for user: {}", user_id_text);
            return Ok(Json(Err(ApiError::Unauthorized)));
        }
    }

    // Fetch user metadata
    let user_metadata = match fetch_user_metadata(dragonfly_service, key_prefix, &user_id_text).await {
        Ok(metadata) => metadata,
        Err(_) => return Ok(Json(Err(ApiError::MetadataNotFound))),
    };

    // Get notification key
    let Some(notification_key) = user_metadata.notification_key else {
        log::warn!("Notification key not found for user: {}", user_id_text);
        return Ok(Json(Err(ApiError::NotificationKeyNotFound)));
    };

    // Send notification
    fcm_service
        .send_message_to_group(notification_key, req.0)
        .await?;

    log::info!("Successfully sent notification for user: {}", user_id_text);
    Ok(Json(Ok(())))
}
