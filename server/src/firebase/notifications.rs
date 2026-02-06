use std::env;

use reqwest::Client;
use serde_json::json;
use types::NotificationKey;
use types::SendNotificationReq;

use crate::firebase::Firebase;

use crate::Error;
use crate::Result;

pub mod utils {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Operation {
        Create,
        Add,
        Remove,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Request {
        pub operation: Operation,
        pub notification_key_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub notification_key: Option<String>,
        pub registration_ids: Vec<String>,
    }

    #[derive(Deserialize)]
    pub struct NotificationKeyResponse {
        pub notification_key: String,
    }

    pub fn get_notification_key_name_from_principal(principal_id: &String) -> String {
        format!("notification_key_{}", principal_id)
    }

    pub fn get_create_request_body(
        notification_key_name: String,
        registration_token: String,
    ) -> Request {
        Request {
            operation: Operation::Create,
            notification_key_name,
            notification_key: None,
            registration_ids: vec![registration_token],
        }
    }

    pub fn get_add_request_body(
        notification_key_name: String,
        notification_key: String,
        registration_token: String,
    ) -> Request {
        Request {
            operation: Operation::Add,
            notification_key_name,
            notification_key: Some(notification_key),
            registration_ids: vec![registration_token],
        }
    }

    pub fn get_remove_request_body(
        notification_key_name: String,
        notification_key: String,
        registration_token: String,
    ) -> Request {
        Request {
            operation: Operation::Remove,
            notification_key_name,
            notification_key: Some(notification_key),
            registration_ids: vec![registration_token],
        }
    }
}

impl Firebase {
    pub async fn get_notification_key(&self, notification_key_name: &str) -> Result<String> {
        let client = Client::new();
        let url = format!(
            "https://fcm.googleapis.com/fcm/notification?notification_key_name={}",
            notification_key_name
        );

        let firebase_token = self
            .get_access_token(&["https://www.googleapis.com/auth/firebase.messaging"])
            .await?;

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", firebase_token))
            .header(
                "project_id",
                env::var("GOOGLE_CLIENT_NOTIFICATIONS_SENDER_ID")
                    .map_err(|e| Error::Unknown(e.to_string()))?,
            )
            .header("access_token_auth", "true")
            .send()
            .await;

        match response {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Failed to read error body".to_string());
                    log::error!(
                        "[get_notification_key] Failed to retrieve key for '{}': Status: {}, Body: {}",
                        notification_key_name, status, error_text
                    );
                    return Err(Error::FirebaseApiErr(error_text));
                }

                let body: utils::NotificationKeyResponse = response.json().await.map_err(|e| {
                    Error::FirebaseApiErr(format!(
                        "Failed to parse get_notification_key response: {}",
                        e
                    ))
                })?;

                Ok(body.notification_key)
            }
            Err(err) => {
                log::error!("[get_notification_key] Request failed: {:?}", err);
                Err(Error::FirebaseApiErr(err.to_string()))
            }
        }
    }

    pub async fn update_notification_devices(
        &self,
        body: serde_json::Value,
    ) -> Result<Option<String>> {
        let is_remove_operation = body
            .get("operation")
            .and_then(|v| v.as_str())
            .map(|s| s == "remove")
            .unwrap_or(false);

        let client = Client::new();
        let url = "https://fcm.googleapis.com/fcm/notification";

        log::info!(
            "[update_notification_devices] Operation: {}, Request body: {:?}",
            body.get("operation")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown"),
            body
        );

        let firebase_token = self
            .get_access_token(&["https://www.googleapis.com/auth/firebase.messaging"])
            .await?;
        let response = client
            .post(url)
            .header("Authorization", format!("Bearer {}", firebase_token))
            .header(
                "project_id",
                env::var("GOOGLE_CLIENT_NOTIFICATIONS_SENDER_ID")
                    .map_err(|e| Error::Unknown(e.to_string()))?,
            )
            .header("access_token_auth", "true")
            .json(&body)
            .send()
            .await;

        match response {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Failed to read error body".to_string());
                    log::error!(
                        "[update_notification_devices] FCM device group operation failed: Status: {}, Body: {}",
                        status,
                        error_text
                    );
                    return Err(Error::FirebaseApiErr(error_text));
                }

                if is_remove_operation {
                    log::info!(
                        "[update_notification_devices] Successfully removed device from group"
                    );
                    return Ok(None);
                }

                match response.json::<utils::NotificationKeyResponse>().await {
                    Ok(parsed) => {
                        log::info!(
                            "[update_notification_devices] Successfully updated device group, notification_key: {}",
                            parsed.notification_key
                        );
                        Ok(Some(parsed.notification_key))
                    }
                    Err(err) => Err(Error::FirebaseApiErr(format!(
                        "error parsing json response: {}",
                        err
                    ))),
                }
            }
            Err(err) => {
                log::error!("[update_notification_devices] Request failed: {:?}", err);
                Err(Error::FirebaseApiErr(err.to_string()))
            }
        }
    }

    pub async fn send_message_to_group(
        &self,
        notification_key: NotificationKey,
        SendNotificationReq {
            notification,
            data,
            android,
            webpush,
            apns,
            fcm_options,
        }: SendNotificationReq,
    ) -> Result<()> {
        let client = Client::new();
        let project_id_string =
            env::var("GOOGLE_CLIENT_NOTIFICATIONS_PROJECT_ID").map_err(|e| {
                Error::Unknown(format!(
                    "Missing GOOGLE_CLIENT_NOTIFICATIONS_PROJECT_ID: {}",
                    e
                ))
            })?;
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            project_id_string
        );

        log::info!(
            "[send_message_to_group] Sending to device group with {} tokens using notification_key",
            notification_key.registration_tokens.len()
        );

        let firebase_token = self
            .get_access_token(&["https://www.googleapis.com/auth/firebase.messaging"])
            .await?;

        // Use notification_key as the token - FCM v1 API supports device groups this way
        let message_body = json!({
            "message": {
                "token": notification_key.key,
                "notification": notification,
                "data": data,
                "android": android,
                "webpush": webpush,
                "apns": apns,
                "fcm_options": fcm_options
            }
        });

        let response = client
            .post(url)
            .header("Authorization", format!("Bearer {}", firebase_token))
            .header("Content-Type", "application/json")
            .json(&message_body)
            .send()
            .await;

        match response {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Failed to read error body".to_string());
                    log::error!(
                        "[send_message_to_group] FCM send failed: Status: {}, Body: {}",
                        status,
                        error_text
                    );
                    Err(Error::FirebaseApiErr(format!(
                        "FCM send failed: {} - {}",
                        status, error_text
                    )))
                } else {
                    let response_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Failed to read success body".to_string());
                    log::info!(
                        "[send_message_to_group] Successfully sent to device group. Response: {:?}",
                        response_text
                    );
                    Ok(())
                }
            }
            Err(err) => {
                log::error!("[send_message_to_group] Request failed: {:?}", err);
                Err(Error::FirebaseApiErr(err.to_string()))
            }
        }
    }
}
