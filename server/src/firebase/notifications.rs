use std::collections::HashMap;
use std::env;

use reqwest::Client;
use serde_json::json;
use types::NotificationKey;

use crate::firebase::Firebase;
use crate::Error;
use crate::Result;

pub mod utils {
    use serde::{Deserialize, Serialize};

    use crate::error::{Error, Result};

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

    pub fn get_notification_key_name_from_principal(principal_id: &String) -> String {
        format!("notification_key_{}", principal_id)
    }

    pub fn get_create_request_body(
        notification_key_name: String,
        registration_token: String,
    ) -> Result<String> {
        serde_json::to_string(&Request {
            operation: Operation::Create,
            notification_key_name,
            notification_key: None,
            registration_ids: vec![registration_token],
        })
        .map_err(|e| Error::Unknown(e.to_string()))
    }

    pub fn get_add_request_body(
        notification_key_name: String,
        notification_key: String,
        registration_token: String,
    ) -> Result<String> {
        serde_json::to_string(&Request {
            operation: Operation::Add,
            notification_key_name,
            notification_key: Some(notification_key),
            registration_ids: vec![registration_token],
        })
        .map_err(|e| Error::Unknown(e.to_string()))
    }

    pub fn get_remove_request_body(
        notification_key_name: String,
        notification_key: String,
        registration_token: String,
    ) -> Result<String> {
        serde_json::to_string(&Request {
            operation: Operation::Remove,
            notification_key_name,
            notification_key: Some(notification_key),
            registration_ids: vec![registration_token],
        })
        .map_err(|e| Error::Unknown(e.to_string()))
    }
}

impl Firebase {
    pub async fn get_notification_key(&self, notification_key_name: &str) -> Result<Option<String>> {
        let client = Client::new();
        // Ensure the URL is correctly encoded if notification_key_name can have special characters,
        // though principal IDs are typically URL-safe. For now, direct interpolation.
        let url = format!("https://fcm.googleapis.com/fcm/notification?notification_key_name={}", notification_key_name);

        let firebase_token = self
            .get_access_token(&["https://www.googleapis.com/auth/firebase.messaging"])
            .await?;
        let sender_id = env::var("GOOGLE_CLIENT_NOTIFICATIONS_SENDER_ID")
            .map_err(|e| Error::Unknown(format!("Missing GOOGLE_CLIENT_NOTIFICATIONS_SENDER_ID: {}", e)))?;

        log::debug!("[get_notification_key] Requesting key for name: {}", notification_key_name);

        let response_result = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", firebase_token))
            .header("Content-Type", "application/json")
            .header("project_id", sender_id)
            .header("access_token_auth", "true")
            .send()
            .await;

        match response_result {
            Ok(response) => {
                let status = response.status();
                let response_body_text = response
                    .text()
                    .await
                    .map_err(|e| Error::Unknown(format!("Failed to read response body from get_notification_key: {}", e)))?;

                if status.is_success() {
                    match serde_json::from_str::<HashMap<String, String>>(&response_body_text) {
                        Ok(json_map) => {
                            if let Some(key) = json_map.get("notification_key") {
                                log::info!("[get_notification_key] Successfully retrieved key for {}: {}", notification_key_name, key);
                                Ok(Some(key.clone()))
                            } else {
                                log::warn!("[get_notification_key] Successful response for {} but no 'notification_key' field. Body: {}", notification_key_name, response_body_text);
                                // Treat as not found if key field is missing despite success status
                                Ok(None)
                            }
                        }
                        Err(e) => {
                            log::error!("[get_notification_key] Failed to parse successful JSON response for {}. Status: {}, Body: {}. Error: {}", notification_key_name, status, response_body_text, e);
                            Err(Error::FirebaseApiErr(format!("Failed to parse get_notification_key success response body: {}, error: {}", response_body_text, e)))
                        }
                    }
                } else {
                    // HTTP error status
                    log::warn!("[get_notification_key] Request for {} failed with status {}. Body: {}", notification_key_name, status, response_body_text);
                    // FCM often returns 404 with {"error": "notification_key not found"} or similar for non-existent keys.
                    // Also, sometimes it might be other 4xx errors that mean "not found".
                    if status == reqwest::StatusCode::NOT_FOUND || response_body_text.contains("notification_key not found") || response_body_text.contains("NOT_FOUND") {
                        Ok(None)
                    } else {
                        Err(Error::FirebaseApiErr(format!("Firebase GET notification_key failed for {} (Status {}): {}", notification_key_name, status, response_body_text)))
                    }
                }
            }
            Err(e) => {
                log::error!("[get_notification_key] HTTP request failed for {}: {}", notification_key_name, e);
                Err(Error::FirebaseApiErr(format!("get_notification_key HTTP request error: {}", e)))
            }
        }
    }

    pub async fn update_notification_devices(&self, data: String) -> Result<Option<String>> {
        let is_remove_operation = data.contains("remove");
        log::debug!("[update_notification_devices] Data: {}, Is Remove: {}", data, is_remove_operation);

        let client = Client::new();
        let url = "https://fcm.googleapis.com/fcm/notification";

        let firebase_token = self
            .get_access_token(&["https://www.googleapis.com/auth/firebase.messaging"])
            .await?;
        let project_sender_id = env::var("GOOGLE_CLIENT_NOTIFICATIONS_SENDER_ID")
            .map_err(|e| Error::Unknown(format!("Missing GOOGLE_CLIENT_NOTIFICATIONS_SENDER_ID: {}", e)))?;

        let response_result = client
            .post(url)
            .header("Authorization", format!("Bearer {}", firebase_token))
            .header("Content-Type", "application/json")
            .header("project_id", project_sender_id)
            .header("access_token_auth", "true")
            .body(data.clone()) // Clone data for logging if needed
            .send()
            .await;

        match response_result {
            Ok(response) => {
                let response_status = response.status();
                let response_body_text = response
                    .text()
                    .await
                    .map_err(|e| Error::Unknown(format!("Failed to read response body from update_notification_devices: {}", e)))?;

                if !response_status.is_success() {
                    log::error!("[update_notification_devices] Error updating. Status: {}. Body: {}", response_status, response_body_text);
                    return Err(Error::FirebaseApiErr(response_body_text));
                }

                // HTTP status is success (2xx)
                if is_remove_operation {
                    log::info!("[update_notification_devices] Remove operation successful. Body: {}", response_body_text);
                    return Ok(None);
                }

                // For create/add, expect a JSON with "notification_key"
                match serde_json::from_str::<HashMap<String, String>>(&response_body_text) {
                    Ok(json_map) => {
                        if let Some(key) = json_map.get("notification_key") {
                            log::info!("[update_notification_devices] Create/Add successful. Received key: {}. Body: {}", key, response_body_text);
                            Ok(Some(key.clone()))
                        } else if let Some(error_val) = json_map.get("error") {
                            log::error!("[update_notification_devices] FCM returned 2xx status with error in JSON: {}. Full body: {}", error_val, response_body_text);
                            Err(Error::FirebaseApiErr(response_body_text)) // Return the full error body from FCM
                        } else {
                            log::error!("[update_notification_devices] FCM returned 2xx status but no 'notification_key' or 'error' field. Body: {}", response_body_text);
                            Err(Error::FirebaseApiErr(format!("FCM success response missing notification_key and error fields: {}", response_body_text)))
                        }
                    }
                    Err(parse_err) => {
                        log::error!("[update_notification_devices] Failed to parse successful JSON response from FCM (Status {}): {}. Body: {}", response_status, parse_err, response_body_text);
                        Err(Error::FirebaseApiErr(format!("FCM returned unparsable success response (Status {}): {}. Body: {}", response_status, parse_err, response_body_text)))
                    }
                }
            }
            Err(err) => {
                log::error!("[update_notification_devices] Reqwest error: {:?}. Original data: {}", err, data);
                Err(Error::FirebaseApiErr(err.to_string()))
            }
        }
    }

    pub async fn send_message_to_group(
        &self,
        notification_key: NotificationKey,
        data_payload: serde_json::Value,
    ) -> Result<()> {
        log::info!("[send_message_to_group] Entered. Notification Key: {}, Data: {:?}", notification_key.key, data_payload);

        let client = Client::new();
        let project_id_string = env::var("GOOGLE_CLIENT_NOTIFICATIONS_PROJECT_ID").map_err(|e| {
            Error::Unknown(format!(
                "Missing GOOGLE_CLIENT_NOTIFICATIONS_PROJECT_ID: {}",
                e
            ))
        })?;
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            project_id_string
        );
        log::info!("[send_message_to_group] FCM URL: {}", url);

        let firebase_token = self
            .get_access_token(&["https://www.googleapis.com/auth/firebase.messaging"])
            .await?;

        let message_body = json!({
            "message": {
                "token": notification_key.key,
                "data": data_payload
            }
        });
        log::info!("[send_message_to_group] FCM Message Body: {:?}", message_body);

        let response = client
            .post(url)
            .header("Authorization", format!("Bearer {}", firebase_token))
            .header("Content-Type", "application/json")
            .json(&message_body) // Send the JSON payload
            .send()
            .await;

        match response {
            Ok(response) => {
                let status = response.status(); // Clone status before consuming body
                if !status.is_success() {
                    let error_text = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Failed to read error body".to_string());
                    log::error!(
                        "Error sending FCM message: Status: {}, Body: {}",
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
                        "Successfully sent FCM message. Response: {:?}",
                        response_text
                    );
                    Ok(())
                }
            }
            Err(err) => {
                log::error!("Error sending FCM message request: {:?}", err);
                Err(Error::FirebaseApiErr(err.to_string()))
            }
        }
    }
}
