use redis::{FromRedisValue, RedisResult, ToRedisArgs, ToSingleRedisArg};

use crate::{
    firebase::Firebase,
    notifications::traits::{
        FcmService, RedisConnection, RegisterDeviceRequest, UnregisterDeviceRequest,
    },
    utils::error::{Error, Result},
};

// Corrected import for types crate
use types::{
    DeviceRegistrationToken, NotificationKey, RegisterDeviceReq, SendNotificationReq, Signature,
    UnregisterDeviceReq,
};

// --- Implement FcmService for Firebase ---
impl FcmService for Firebase {
    async fn get_notification_key(&self, notification_key_name: &str) -> Result<String, Error> {
        self.get_notification_key(notification_key_name).await
    }

    async fn update_notification_devices(
        &self,
        body: serde_json::Value,
    ) -> Result<Option<String>, Error> {
        self.update_notification_devices(body).await
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
impl RedisConnection for redis::aio::MultiplexedConnection {
    async fn hget<F, RV>(&mut self, key: &str, field: F) -> RedisResult<RV>
    where
        F: ToSingleRedisArg + Send + Sync,
        RV: FromRedisValue + Send + Sync,
    {
        let mut conn = self.clone();
        redis::AsyncCommands::hget(&mut conn, key, field).await
    }

    async fn hset<K, F, V>(&mut self, key: K, field: F, value: V) -> RedisResult<bool>
    where
        K: ToSingleRedisArg + Send + Sync,
        F: ToSingleRedisArg + Send + Sync,
        V: ToSingleRedisArg + Send + Sync,
    {
        let mut conn = self.clone();
        redis::AsyncCommands::hset(&mut conn, key, field, value).await
    }
}

impl RedisConnection for redis::aio::ConnectionManager {
    async fn hget<F, RV>(&mut self, key: &str, field: F) -> RedisResult<RV>
    where
        F: ToSingleRedisArg + Send + Sync,
        RV: FromRedisValue + Send + Sync,
    {
        redis::AsyncCommands::hget(self, key, field).await
    }

    async fn hset<K, F, V>(&mut self, key: K, field: F, value: V) -> RedisResult<bool>
    where
        K: ToSingleRedisArg + Send + Sync,
        F: ToSingleRedisArg + Send + Sync,
        V: ToSingleRedisArg + Send + Sync,
    {
        redis::AsyncCommands::hset(self, key, field, value).await
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
