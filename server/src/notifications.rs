use std::collections::HashMap;

use candid::Principal;
use ntex::web::{
    self,
    types::{Json, Path, State},
};
use redis::AsyncCommands;
use reqwest::Client;
use types::{
    error::ApiError, ApiResult, DeviceRegistrationToken, NotificationKey, RegisterDeviceReq,
    RegisterDeviceRes, UnregisterDeviceReq, UnregisterDeviceRes, UserMetadata,
};

use crate::{api::METADATA_FIELD, state::AppState, Error, Result};

#[web::post("/notifications/{user_principal}")]
async fn register_device(
    state: State<AppState>,
    user_principal: Path<Principal>,
    req: Json<RegisterDeviceReq>,
) -> Result<Json<ApiResult<RegisterDeviceRes>>> {
    // Verify the identity of the sender
    let signature = req.0.signature;
    let registration_token = req.0.registration_token;
    signature.verify_identity(*user_principal.as_ref(), registration_token.clone().into())?;

    // Get the user metadata
    let mut conn = state.redis.get().await?;
    let user = user_principal.to_text();
    let meta_raw: Option<Box<[u8]>> = conn.hget(&user, METADATA_FIELD).await?;
    let Some(meta_raw) = meta_raw else {
        return Ok(Json(Err(ApiError::MetadataNotFound)));
    };
    let mut user_metadata: UserMetadata =
        serde_json::from_slice(&meta_raw).map_err(Error::Deser)?;

    // Register the device with Firebase
    let client = Client::new();
    let url = "https://fcm.googleapis.com/fcm/notification";

    let notification_key_name = format!("notification_key_{}", user);

    let data = if let Some(notification_key) = user_metadata.notification_key.as_ref() {
        format!(
            r#"{{
                "operation": "add",
                "notification_key_name": "{}",
                "notification_key": "{}",
                "registration_ids": ["{}"]
            }}"#,
            notification_key_name, notification_key.key, registration_token.token
        )
    } else {
        format!(
            r#"{{
            "operation": "create",
            "notification_key_name": "{}",
            "registration_ids": ["{}"]
        }}"#,
            notification_key_name, registration_token.token
        )
    };

    // TODO: get the token from the app state
    let firebase_token = state
        .get_access_token(&["https://www.googleapis.com/auth/firebase.messaging"])
        .await;
    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", firebase_token))
        .header("Content-Type", "application/json")
        .header("project_id", "hot-or-not-feed-intelligence")
        .header("access_token_auth", "true")
        .body(data)
        .send()
        .await;

    if response.is_err() || !response.as_ref().unwrap().status().is_success() {
        log::error!("Error registering device: {:?}", response);
        return Ok(Json(Err(ApiError::FirebaseApiError(
            response.unwrap().text().await.unwrap(),
        ))));
    }

    let response = response.unwrap();
    let response = match response.json::<HashMap<String, String>>().await {
        Ok(response) => response,
        Err(err) => {
            return Ok(Json(Err(ApiError::FirebaseApiError(format!(
                "error parsing json: {}",
                err
            )))));
        }
    };

    let notification_key = response["notification_key"].clone();

    if user_metadata.notification_key.as_ref().is_none() {
        user_metadata.notification_key = Some(NotificationKey {
            key: notification_key,
            registration_tokens: vec![DeviceRegistrationToken {
                token: registration_token.token.clone(),
                device_fingerprint: registration_token.device_fingerprint.clone(),
            }],
        });
    } else {
        user_metadata
            .notification_key
            .as_mut()
            .unwrap()
            .registration_tokens
            .push(DeviceRegistrationToken {
                token: registration_token.token.clone(),
                device_fingerprint: registration_token.device_fingerprint.clone(),
            });
    }

    let meta_raw = serde_json::to_vec(&user_metadata).expect("failed to serialize user metadata?!");
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
    signature.verify_identity(*user_principal.as_ref(), registration_token.clone().into())?;

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
    let client = Client::new();
    let url = "https://fcm.googleapis.com/fcm/notification";

    let notification_key_name = format!("notification_key_{}", user);
    let notification_key = match user_metadata.notification_key.as_ref() {
        Some(notification_key) => notification_key,
        None => {
            return Ok(Json(Err(ApiError::NotificationKeyNotFound)));
        }
    };

    let token_to_delete = match notification_key
        .registration_tokens
        .iter()
        .filter(|token| {
            token.token == registration_token.token
                || token.device_fingerprint == registration_token.device_fingerprint
        })
        .map(|token| token.token.clone())
        .next()
    {
        Some(token) => token,
        None => {
            return Ok(Json(Err(ApiError::DeviceNotFound)));
        }
    };

    let data = format!(
        r#"{{
            "operation": "remove",
            "notification_key_name": "{}",
            "notification_key": "{}",
            "registration_ids": ["{}"]
        }}"#,
        notification_key_name, notification_key.key, token_to_delete
    );

    // TODO: get the token from the app state
    let firebase_token = state
        .get_access_token(&["https://www.googleapis.com/auth/firebase.messaging"])
        .await;
    let response = client
        .post(url)
        .header("Authorization", format!("Bearer {}", firebase_token))
        .header("Content-Type", "application/json")
        .header("project_id", "hot-or-not-feed-intelligence")
        .header("access_token_auth", "true")
        .body(data)
        .send()
        .await;

    if response.is_err() || !response.as_ref().unwrap().status().is_success() {
        log::error!("Error deregistering device: {:?}", response);
        return Ok(Json(Err(ApiError::Unknown(
            "Error deregistering device".to_string(),
        ))));
    }

    user_metadata
        .notification_key
        .as_mut()
        .unwrap()
        .registration_tokens
        .retain(|token| {
            token.token != registration_token.token
                || token.device_fingerprint != registration_token.device_fingerprint
        });

    let meta_raw = serde_json::to_vec(&user_metadata).expect("failed to serialize user metadata?!");
    let _replaced: bool = conn.hset(user, METADATA_FIELD, &meta_raw).await?;

    log::info!("Device registered successfully");

    Ok(Json(Ok(())))
}
