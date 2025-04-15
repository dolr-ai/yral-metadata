pub mod error;
use candid::Principal;
use error::ApiError;
use serde::{Deserialize, Serialize};
use yral_identity::{msg_builder::Message, Signature};

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceRegistrationToken {
    pub token: String,
    pub device_fingerprint: String,
}

impl From<DeviceRegistrationToken> for Message {
    fn from(value: DeviceRegistrationToken) -> Self {
        Message::default()
            .method_name("register_device".into())
            .args((value.token, value.device_fingerprint))
            // unwrap is safe here because (String, String) serialization can't fail
            .unwrap()
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

impl From<UserMetadata> for Message {
    fn from(value: UserMetadata) -> Self {
        Message::default()
            .method_name("set_user_metadata".into())
            .args((value.user_canister_id, value.user_name))
            // unwrap is safe here because (Principal, String) serialization can't fail
            .unwrap()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SetUserMetadataReqMetadata {
    pub user_canister_id: Principal,
    pub user_name: String,
}

impl From<SetUserMetadataReqMetadata> for Message {
    fn from(value: SetUserMetadataReqMetadata) -> Self {
        Message::default()
            .method_name("set_user_metadata".into())
            .args((value.user_canister_id, value.user_name))
            // unwrap is safe here because (Principal, String) serialization can't fail
            .unwrap()
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct RegisterDeviceReq {
    pub registration_token: DeviceRegistrationToken,
    pub signature: Signature,
}

pub type RegisterDeviceRes = ();

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct UnregisterDeviceReq {
    pub registration_token: DeviceRegistrationToken,
    pub signature: Signature,
}

pub type UnregisterDeviceRes = ();
