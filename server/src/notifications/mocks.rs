use crate::{
    api::METADATA_FIELD,
    firebase::notifications::utils::{
        Operation as FirebaseUtilOperation, Request as FirebaseUtilRequest,
    },
    notifications::traits::{
        FcmService, RedisConnection, RegisterDeviceRequest, UnregisterDeviceRequest,
    },
    utils::error::{Error, Result},
};
use redis::{FromRedisValue, RedisError, RedisResult, ToRedisArgs};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::sync::RwLock;
use types::{
    DeviceRegistrationToken, NotificationKey, SendNotificationReq, Signature,
    UserMetadata as ActualUserMetadata,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MockRedisConnection {
    pub users_data: HashMap<String, ActualUserMetadata>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct MockUserMetadata {
    pub user_canister_id: String,
    pub user_name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_key: Option<NotificationKey>,
}

impl From<MockUserMetadata> for ActualUserMetadata {
    fn from(mock: MockUserMetadata) -> Self {
        ActualUserMetadata {
            user_canister_id: mock.user_canister_id.parse().unwrap_or_else(|_| {
                panic!(
                    "Mock user_canister_id is not a valid Principal: {}",
                    mock.user_canister_id
                )
            }),
            user_name: mock.user_name,
            notification_key: mock.notification_key,
        }
    }
}

impl From<ActualUserMetadata> for MockUserMetadata {
    fn from(actual: ActualUserMetadata) -> Self {
        MockUserMetadata {
            user_canister_id: actual.user_canister_id.to_text(),
            user_name: actual.user_name,
            notification_key: actual.notification_key,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MockRegisterDeviceReq {
    pub registration_token: DeviceRegistrationToken,
}

impl RegisterDeviceRequest for MockRegisterDeviceReq {
    fn registration_token(&self) -> DeviceRegistrationToken {
        self.registration_token.clone()
    }

    fn signature(&self) -> Option<Signature> {
        None // Mocks typically don't have signatures
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MockUnregisterDeviceReq {
    pub registration_token: DeviceRegistrationToken,
}

impl UnregisterDeviceRequest for MockUnregisterDeviceReq {
    fn registration_token(&self) -> DeviceRegistrationToken {
        self.registration_token.clone()
    }

    fn signature(&self) -> Option<Signature> {
        None // Mocks typically don't have signatures
    }
}

impl MockRedisConnection {
    pub fn new() -> Self {
        Self {
            users_data: HashMap::new(),
        }
    }

    pub fn add_user(&mut self, user_metadata: ActualUserMetadata) {
        self.users_data
            .insert(user_metadata.user_canister_id.to_text(), user_metadata);
    }
}

impl RedisConnection for MockRedisConnection {
    async fn hget<F, RV>(&mut self, key: &str, field: F) -> RedisResult<RV>
    where
        F: ToRedisArgs + Send + Sync,
        RV: FromRedisValue + Send + Sync,
    {
        let field_bytes = field.to_redis_args();
        let field_str =
            String::from_utf8_lossy(field_bytes.get(0).map_or(&Vec::new(), |v| v)).into_owned();

        if field_str != METADATA_FIELD {
            return Ok(RV::from_redis_value(&redis::Value::Nil)?); // Field mismatch, return nil
        }

        match self.users_data.get(key) {
            Some(user_metadata) => {
                // Serialize to JSON bytes, then wrap in redis::Value::Data
                let serialized_data = serde_json::to_vec(user_metadata).map_err(|e| {
                    RedisError::from((
                        redis::ErrorKind::TypeError,
                        "Mock serialization error",
                        e.to_string(),
                    ))
                })?;
                RV::from_redis_value(&redis::Value::Data(serialized_data))
            }
            None => Ok(RV::from_redis_value(&redis::Value::Nil)?), // Key not found, return nil
        }
    }

    async fn hset<K, F, V>(&mut self, key: K, field: F, value: V) -> RedisResult<bool>
    where
        K: ToRedisArgs + Send + Sync,
        F: ToRedisArgs + Send + Sync,
        V: ToRedisArgs + Send + Sync,
    {
        let key_args = key.to_redis_args();
        let key_str =
            String::from_utf8_lossy(key_args.get(0).map_or(&Vec::new(), |v| v)).into_owned();

        let field_args = field.to_redis_args();
        let field_str =
            String::from_utf8_lossy(field_args.get(0).map_or(&Vec::new(), |v| v)).into_owned();

        if field_str != METADATA_FIELD {
            return Err(RedisError::from((
                redis::ErrorKind::TypeError,
                "Mock hset: Invalid field argument",
            )));
        }

        let value_args = value.to_redis_args();
        let value_bytes = value_args.get(0).ok_or_else(|| {
            RedisError::from((
                redis::ErrorKind::TypeError,
                "Mock hset: Value is not valid bytes",
            ))
        })?;

        let user_metadata: ActualUserMetadata =
            serde_json::from_slice(value_bytes).map_err(|e| {
                RedisError::from((
                    redis::ErrorKind::TypeError,
                    "Mock hset: Deserialization error",
                    e.to_string(),
                ))
            })?;

        self.users_data.insert(key_str, user_metadata);
        Ok(true) // Return true for successful set
    }
}

#[derive(Serialize, Deserialize)]
pub struct MockFCM {
    pub notification_groups: RwLock<HashMap<String, DeviceGroup>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceGroup {
    pub notification_key: String,
    pub registration_tokens: Vec<String>,
}

impl MockFCM {
    pub fn new() -> Self {
        Self {
            notification_groups: RwLock::new(HashMap::new()),
        }
    }
}

impl FcmService for MockFCM {
    async fn update_notification_devices(
        &self,
        body: serde_json::Value,
    ) -> Result<Option<String>, Error> {
        let request: FirebaseUtilRequest = serde_json::from_value(body).map_err(|e| {
            Error::Unknown(format!(
                "MockFCM: Failed to deserialize request body: {}",
                e
            ))
        })?;

        let mut groups = self.notification_groups.write().unwrap();
        let registration_token = request
            .registration_ids
            .get(0)
            .ok_or_else(|| {
                Error::Unknown("MockFCM: Missing registration_token in request_ids".to_string())
            })?
            .clone();

        match request.operation {
            FirebaseUtilOperation::Create => {
                if let Some(existing_group) = groups.get(&request.notification_key_name) {
                    let error_json = serde_json::json!({ "error": "notification_key_name exists", "notification_key": existing_group.notification_key }).to_string();
                    return Err(Error::FirebaseApiErr(error_json));
                }
                groups.insert(
                    request.notification_key_name.clone(),
                    DeviceGroup {
                        notification_key: request.notification_key_name.clone(),
                        registration_tokens: vec![registration_token],
                    },
                );
                Ok(Some(request.notification_key_name))
            }
            FirebaseUtilOperation::Add => {
                let key_to_use = request.notification_key.as_ref().ok_or_else(|| {
                    Error::Unknown(
                        "MockFCM: notification_key missing for Add operation".to_string(),
                    )
                })?;
                if let Some(group) = groups.get_mut(&request.notification_key_name) {
                    if group.notification_key != *key_to_use {
                        return Err(Error::FirebaseApiErr(
                            "MockFCM: notification_key mismatch for Add operation".to_string(),
                        ));
                    }
                    if !group.registration_tokens.contains(&registration_token) {
                        group.registration_tokens.push(registration_token);
                    }
                    Ok(Some(group.notification_key.clone()))
                } else {
                    Err(Error::FirebaseApiErr(
                        "MockFCM: notification_key_name not found for Add operation".to_string(),
                    ))
                }
            }
            FirebaseUtilOperation::Remove => {
                let key_to_use = request.notification_key.as_ref().ok_or_else(|| {
                    Error::Unknown(
                        "MockFCM: notification_key missing for Remove operation".to_string(),
                    )
                })?;
                if let Some(group) = groups.get_mut(&request.notification_key_name) {
                    if group.notification_key != *key_to_use {
                        return Err(Error::FirebaseApiErr(
                            "MockFCM: notification_key mismatch for Remove operation".to_string(),
                        ));
                    }
                    group
                        .registration_tokens
                        .retain(|t| t != &registration_token);
                    Ok(None)
                } else {
                    Err(Error::FirebaseApiErr(
                        "MockFCM: notification_key_name not found for Remove operation".to_string(),
                    ))
                }
            }
        }
    }

    async fn send_message_to_group(
        &self,
        notification_key: NotificationKey,
        data_payload: SendNotificationReq,
    ) -> Result<(), Error> {
        let groups = self.notification_groups.read().unwrap();
        if let Some(_group) = groups
            .iter()
            .find(|(_, g)| g.notification_key == notification_key.key)
        {
            println!(
                "Mock sending message to group: {:?} with payload: {:?}",
                notification_key.key, data_payload
            );
            Ok(())
        } else {
            Err(Error::Unknown(format!(
                "Notification key not found in mock: {:?}",
                notification_key.key
            )))
        }
    }
}
