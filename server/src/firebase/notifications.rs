use std::collections::HashMap;
use std::env;

use reqwest::Client;
use serde_json::json;
use types::NotificationKey;
use types::NotificationPayload;

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
    pub async fn update_notification_devices(&self, data: String) -> Result<Option<String>> {
        let is_remove_operation = data.contains("remove");

        let client = Client::new();
        let url = "https://fcm.googleapis.com/fcm/notification";

        let firebase_token = self
            .get_access_token(&["https://www.googleapis.com/auth/firebase.messaging"])
            .await?;
        let response = client
            .post(url)
            .header("Authorization", format!("Bearer {}", firebase_token))
            .header("Content-Type", "application/json")
            .header(
                "project_id",
                env::var("GOOGLE_CLIENT_NOTIFICATIONS_SENDER_ID")
                    .map_err(|e| Error::Unknown(e.to_string()))?,
            )
            .header("access_token_auth", "true")
            .body(data)
            .send()
            .await;

        match response {
            Ok(response) => {
                if !response.status().is_success() {
                    log::error!("Error updating notification devices: {:?}", response);
                    return Err(Error::FirebaseApiErr(
                        response
                            .text()
                            .await
                            .map_err(|e| Error::Unknown(e.to_string()))?,
                    ));
                }

                if is_remove_operation {
                    return Ok(None);
                }

                match response.json::<HashMap<String, String>>().await {
                    Ok(response) => Ok(Some(response["notification_key"].clone())),
                    Err(err) => Err(Error::FirebaseApiErr(format!(
                        "error parsing json: {}",
                        err
                    ))),
                }
            }
            Err(err) => {
                log::error!("Error updating notification devices: {:?}", err);
                Err(Error::FirebaseApiErr(err.to_string()))
            }
        }
    }

    pub async fn send_message_to_group(
        &self,
        notification_key: NotificationKey,
        data_payload: NotificationPayload,
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
        log::info!("[send_message_to_group] FCM URL: {}", url);

        let firebase_token = self
            .get_access_token(&["https://www.googleapis.com/auth/firebase.messaging"])
            .await?;

        let message_body = json!({
            "message": {
                "token": notification_key.key,
                "notification": data_payload
            }
        });
        log::info!(
            "[send_message_to_group] FCM Message Body: {:?}",
            message_body
        );

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
