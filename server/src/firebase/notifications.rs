use std::collections::HashMap;

use reqwest::Client;

use crate::firebase::Firebase;
use crate::Error;
use crate::Result;

pub mod utils {
    pub fn get_notification_key_name_from_principal(principal_id: &String) -> String {
        format!("notification_key_{}", principal_id)
    }

    pub fn get_create_request_body(
        notification_key_name: String,
        notification_key: String,
    ) -> String {
        format!(
            r#"{{
                "operation": "create",
                "notification_key_name": "{}",
                "notification_key": "{}"
            }}"#,
            notification_key_name, notification_key
        )
    }

    pub fn get_add_request_body(
        notification_key_name: String,
        notification_key: String,
        registration_token: String,
    ) -> String {
        format!(
            r#"{{
                "operation": "add",
                "notification_key_name": "{}",
                "notification_key": "{}",
                "registration_ids": ["{}"]
            }}"#,
            notification_key_name, notification_key, registration_token
        )
    }

    pub fn get_remove_request_body(
        notification_key_name: String,
        notification_key: String,
        registration_token: String,
    ) -> String {
        format!(
            r#"{{
                "operation": "remove",
                "notification_key_name": "{}",
                "notification_key": "{}",
                "registration_ids": ["{}"]
            }}"#,
            notification_key_name, notification_key, registration_token
        )
    }
}

impl Firebase {
    pub async fn update_notification_devices(&self, data: String) -> Result<Option<String>> {
        let is_remove_operation = data.contains("remove");

        let client = Client::new();
        let url = "https://fcm.googleapis.com/fcm/notification";

        let firebase_token = self
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
            log::error!("Error updating notification devices: {:?}", response);
            return Err(Error::FirebaseApiError(
                response.unwrap().text().await.unwrap(),
            ));
        }

        if is_remove_operation {
            return Ok(None);
        }

        let response = response.unwrap();
        let response = match response.json::<HashMap<String, String>>().await {
            Ok(response) => response,
            Err(err) => {
                return Err(Error::FirebaseApiError(format!(
                    "error parsing json: {}",
                    err
                )));
            }
        };

        Ok(Some(response["notification_key"].clone()))
    }
}
