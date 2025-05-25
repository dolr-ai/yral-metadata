use crate::{
    utils::error::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use types::{DeviceRegistrationToken, NotificationKey, NotificationPayload};
use serde_json;

#[derive(Serialize, Deserialize)]
pub struct MockRedisConnection {
    pub users: Vec<MockUserMetadata>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct MockUserMetadata {
    pub user_canister_id: String,
    pub user_name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_key: Option<NotificationKey>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MockRegisterDeviceReq {
    pub registration_token: DeviceRegistrationToken,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MockUnregisterDeviceReq {
    pub registration_token: DeviceRegistrationToken,
}

impl MockRedisConnection {
    pub fn new() -> Self {
        Self { users: vec![] }
    }

    pub async fn hget(&self, key: &str) -> Result<Option<MockUserMetadata>, String> {
        Ok(self
            .users
            .iter()
            .find(|user| user.user_canister_id == key)
            .cloned())
    }

    pub async fn hset(&mut self, _key: &str, value: MockUserMetadata) -> Result<bool, String> {
        Ok(self
            .users
            .iter_mut()
            .find(|user| user.user_name == value.user_name)
            .map(|user| {
                *user = value;
                true
            })
            .is_some())
    }
}

#[derive(Serialize, Deserialize)]
pub struct MockFCM {
    pub notification_groups: HashMap<String, DeviceGroup>,
}

#[derive(Serialize, Deserialize)]
pub struct DeviceGroup {
    pub notification_key: String,
    pub registration_tokens: Vec<String>,
}
pub enum MockFCMEnum {
    Create,
    Add,
    Remove,
}

impl MockFCM {
    pub fn new() -> Self {
        Self {
            notification_groups: HashMap::new(),
        }
    }

    pub fn update_notification_devices(
        &mut self,
        op: MockFCMEnum,
        notification_key_name: String,
        registration_token: String,
    ) -> Result<Option<String>, Error> {
        match op {
            MockFCMEnum::Create => {
                if let Some(existing_group) = self.notification_groups.get(&notification_key_name) {
                    let error_json = serde_json::json!({ "error": "notification_key_name exists", "notification_key": existing_group.notification_key }).to_string();
                    return Err(Error::FirebaseApiErr(error_json));
                }
                self.notification_groups.insert(
                    notification_key_name.clone(),
                    DeviceGroup {
                        notification_key: notification_key_name.clone(),
                        registration_tokens: vec![registration_token],
                    },
                );
                Ok(Some(notification_key_name))
            }
            MockFCMEnum::Add => {
                if let Some(group) = self.notification_groups.get_mut(&notification_key_name) {
                    group.registration_tokens.push(registration_token);
                    Ok(Some(group.notification_key.clone()))
                } else {
                    Err(Error::FirebaseApiErr(
                        "notification_key not found".to_string(),
                    ))
                }
            }
            MockFCMEnum::Remove => {
                if let Some(tokens) = self.notification_groups.get_mut(&notification_key_name) {
                    if let Some(index) = tokens
                        .registration_tokens
                        .iter()
                        .position(|t| t == &registration_token)
                    {
                        tokens.registration_tokens.remove(index);
                        if tokens.registration_tokens.is_empty() {
                            self.notification_groups.remove(&notification_key_name);
                        }
                    }
                }
                Ok(None)
            }
        }
    }

    pub fn send_message_to_group(
        &mut self,
        notification_key: String,
        data_payload: NotificationPayload,
    ) -> Result<Option<String>, Error> {
        if let Some(group) = self
            .notification_groups
            .iter()
            .find(|(_, group)| group.notification_key == notification_key)
        {
            println!(
                "Mock sending message to group: {:?} with payload: {:?}",
                notification_key, data_payload
            );
        } else {
            return Err(Error::Unknown(format!(
                "Notification key not found: {:?}",
                notification_key
            )));
        }
        Ok(None)
    }
}
