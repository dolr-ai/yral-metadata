use redis::{FromRedisValue, ToRedisArgs};

use crate::{
    firebase::Firebase,
    notifications::traits::{
        FcmService, RedisConnection, RegisterDeviceRequest, UnregisterDeviceRequest,
    },
    state::PooledConn,
    utils::error::{Error, Result},
};

// Corrected import for types crate
use types::{
    DeviceRegistrationToken, NotificationKey, RegisterDeviceReq, SendNotificationReq, Signature,
    UnregisterDeviceReq,
};

// --- Implement FcmService for Firebase ---
impl FcmService for Firebase {
    async fn update_notification_devices(
        &self,
        body: serde_json::Value,
    ) -> Result<Option<String>, Error> {
        let body_str = body.to_string();
        self.update_notification_devices(body_str).await
    }

    async fn send_message_to_group(
        &self,
        notification_key: NotificationKey,
        data_payload: SendNotificationReq,
    ) -> Result<(), Error> {
        self.send_message_to_group(notification_key, data_payload)
            .await
    }
}

// --- Implement RedisConnection for redis::aio::MultiplexedConnection ---
impl RedisConnection for PooledConn<'_> {
    async fn hget<RV>(&mut self, key: &str, field: &str) -> Result<RV>
    where
        RV: FromRedisValue + Send + Sync,
    {
        self.hget(key, field).await
    }

    async fn hset<K, V>(&mut self, key: K, field: &str, value: V) -> Result<()>
    where
        K: ToRedisArgs + Send + Sync + Clone,
        V: ToRedisArgs + Send + Sync,
    {
        self.hset(key, field, &value).await
    }
}

// --- Implement RegisterDeviceRequest for types::RegisterDeviceReq ---
impl RegisterDeviceRequest for RegisterDeviceReq {
    fn registration_token(&self) -> DeviceRegistrationToken {
        self.registration_token.clone()
    }

    fn signature(&self) -> Option<Signature> {
        Some(self.signature.clone())
    }
}

// --- Implement UnregisterDeviceRequest for types::UnregisterDeviceReq ---
impl UnregisterDeviceRequest for UnregisterDeviceReq {
    fn registration_token(&self) -> DeviceRegistrationToken {
        self.registration_token.clone()
    }

    fn signature(&self) -> Option<Signature> {
        Some(self.signature.clone())
    }
}

// Note: UserPrincipal is already implemented for ntex::web::types::Path<Principal> and String
// in traits.rs itself.

// Mock implementations will go into mocks.rs or a new mocks_impl.rs
