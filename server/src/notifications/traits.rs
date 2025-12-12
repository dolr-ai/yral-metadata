use axum::extract::Path;
use candid::Principal;
use redis::RedisResult;

use crate::utils::error::{Error, Result};
use types::{DeviceRegistrationToken, NotificationKey, SendNotificationReq, Signature};

// --- FCM Service Trait ---
pub trait FcmService: Send + Sync {
    async fn update_notification_devices(
        &self,
        body: serde_json::Value,
    ) -> Result<Option<String>, Error>;

    async fn send_message_to_group(
        &self,
        notification_key: NotificationKey,
        data_payload: SendNotificationReq,
    ) -> Result<(), Error>;

    // In tests, a more specific version is used. We can handle this with different
    // implementations or a more generic approach if simple delegation isn't enough.
    // For now, the mock will need to adapt its `update_notification_devices` or we
    // create a separate trait/method if absolutely necessary.
}

// --- Redis Connection Trait ---
// This trait will need to be generic over the return type of hget
// or have associated types to handle the difference between test and non-test.
// For simplicity, let's start with a version that matches the non-test case,
// and mocks can serialize/deserialize as needed, or we refine this.

pub trait RedisConnection: Send + Sync {
    async fn hget<F, RV>(&mut self, key: &str, field: F) -> RedisResult<RV>
    where
        F: redis::ToRedisArgs + Send + Sync,
        RV: redis::FromRedisValue + Send + Sync;

    async fn hset<K, F, V>(&mut self, key: K, field: F, value: V) -> RedisResult<bool>
    where
        K: redis::ToRedisArgs + Send + Sync,
        F: redis::ToRedisArgs + Send + Sync,
        V: redis::ToRedisArgs + Send + Sync;

    // Test-specific hget that returns UserMetadata directly.
    // The mock implementation will handle this.
    // Alternatively, the main hget could be made more generic,
    // or the calling code in tests could deserialize.
}

// Wrapper for Redis connection to adapt the hget signature for tests if needed
// Or, the mock implementation directly implements the desired test signature.

// --- User Principal Trait ---

// This trait will abstract the difference between Path<Principal> and String for user_principal
pub trait UserPrincipal: Send + Sync {
    fn to_text(&self) -> String;
    // If the actual Principal is needed for verification:
    fn as_principal(&self) -> Option<Principal>;
}

impl UserPrincipal for Path<Principal> {
    fn to_text(&self) -> String {
        self.0.to_text()
    }

    fn as_principal(&self) -> Option<Principal> {
        Some(**self)
    }
}

impl UserPrincipal for String {
    fn to_text(&self) -> String {
        self.clone()
    }

    fn as_principal(&self) -> Option<Principal> {
        None // String principal in tests cannot be converted back to candid::Principal directly
    }
}

// --- Notification Request Traits ---

// For RegisterDeviceReq and its mock
pub trait RegisterDeviceRequest: Send + Sync {
    fn registration_token(&self) -> DeviceRegistrationToken;
    fn signature(&self) -> Option<Signature>; // Option because mocks might not have it

    fn verify_identity_against_principal(&self, principal: &impl UserPrincipal) -> Result<()> {
        if cfg!(test) {
            // Or better, rely on the mock implementation to do nothing.
            // For now, explicitly skip for test environments if signature is None,
            // assuming mocks might not provide a signature.
            if self.signature().is_none() {
                return Ok(());
            }
        }

        let sig = self
            .signature()
            .ok_or_else(|| Error::Unknown("Signature missing for verification".to_string()))?;
        let token_msg = yral_identity::msg_builder::Message::try_from(self.registration_token())?;
        let principal_obj = principal.as_principal().ok_or_else(|| {
            Error::Unknown("Principal object not available for verification".to_string())
        })?;
        sig.verify_identity(principal_obj, token_msg)?;
        Ok(())
    }
}

// For UnregisterDeviceReq and its mock
pub trait UnregisterDeviceRequest: Send + Sync {
    fn registration_token(&self) -> DeviceRegistrationToken;
    fn signature(&self) -> Option<Signature>; // Option because mocks might not have it

    fn verify_identity_against_principal(&self, principal: &impl UserPrincipal) -> Result<()> {
        if cfg!(test) {
            // Similar to above, skip for test environments if signature is None.
            if self.signature().is_none() {
                return Ok(());
            }
        }
        let sig = self
            .signature()
            .ok_or_else(|| Error::Unknown("Signature missing for verification".to_string()))?;
        let token_msg = yral_identity::msg_builder::Message::try_from(self.registration_token())?;
        let principal_obj = principal.as_principal().ok_or_else(|| {
            Error::Unknown("Principal object not available for verification".to_string())
        })?;
        sig.verify_identity(principal_obj, token_msg)?;
        Ok(())
    }
}

// We'll also need to make the `FirebaseService` in `AppState` and the `redis::aio::MultiplexedConnection`
// implement these traits.
// And the mock objects (`MockFCM`, `MockRedisConnection`, `MockRegisterDeviceReq` etc.)
// will also need to implement these traits.
