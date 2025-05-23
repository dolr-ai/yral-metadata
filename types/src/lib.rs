pub mod error;

use candid::Principal;
use error::ApiError;
use serde::{Deserialize, Serialize};
use yral_identity::{msg_builder::Message, Error, Signature};

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceRegistrationToken {
    pub token: String,
}

impl TryFrom<DeviceRegistrationToken> for Message {
    type Error = Error;
    fn try_from(value: DeviceRegistrationToken) -> Result<Self, Self::Error> {
        Message::default()
            .method_name("register_device".into())
            .args((value.token,))
            .map_err(|_| Error::InvalidMessage("Failed to serialize arguments".to_string()))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct NotificationKey {
    pub key: String,
    pub registration_tokens: Vec<DeviceRegistrationToken>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserMetadata {
    pub user_canister_id: Principal,
    pub user_name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_key: Option<NotificationKey>,
}

impl TryFrom<UserMetadata> for Message {
    type Error = Error;
    fn try_from(value: UserMetadata) -> Result<Self, Self::Error> {
        Message::default()
            .method_name("set_user_metadata".into())
            .args((value.user_canister_id, value.user_name))
            .map_err(|_| Error::InvalidMessage("Failed to serialize arguments".to_string()))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SetUserMetadataReqMetadata {
    pub user_canister_id: Principal,
    pub user_name: String,
}

impl TryFrom<SetUserMetadataReqMetadata> for Message {
    type Error = Error;
    fn try_from(value: SetUserMetadataReqMetadata) -> Result<Self, Self::Error> {
        Message::default()
            .method_name("set_user_metadata".into())
            .args((value.user_canister_id, value.user_name))
            .map_err(|_| Error::InvalidMessage("Failed to serialize arguments".to_string()))
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct SetUserMetadataReq {
    pub metadata: SetUserMetadataReqMetadata,
    pub signature: Signature,
}

pub type SetUserMetadataRes = ();

pub type GetUserMetadataRes = Option<UserMetadata>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct BulkUsers {
    pub users: Vec<Principal>,
}

pub type DeleteMetadataBulkRes = ();

#[derive(Serialize, Deserialize, Clone)]
pub struct RegisterDeviceReq {
    pub registration_token: DeviceRegistrationToken,
    pub signature: Signature,
}

pub type RegisterDeviceRes = ();

#[derive(Serialize, Deserialize, Clone)]
pub struct UnregisterDeviceReq {
    pub registration_token: DeviceRegistrationToken,
    pub signature: Signature,
}

pub type UnregisterDeviceRes = ();

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct NotificationPayload{
    pub title: String,
    pub body: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SendNotificationReq {
    pub data: NotificationPayload,
}

pub type SendNotificationRes = ();

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CanisterSessionRegisteredRes {
    pub success: bool,
    pub error: Option<String>,
    pub referral_success: bool,
}
