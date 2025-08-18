pub mod error;

use candid::Principal;
use error::ApiError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use utoipa::ToSchema;
pub use yral_identity::{msg_builder::Message, Error, Signature};

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, ToSchema)]
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, ToSchema)]
pub struct NotificationKey {
    pub key: String,
    pub registration_tokens: Vec<DeviceRegistrationToken>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, ToSchema)]
pub struct UserMetadata {
    #[schema(value_type = String)]
    pub user_canister_id: Principal,
    pub user_name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_key: Option<NotificationKey>,

    #[serde(default)]
    pub email: Option<String>,

    #[serde(default)]
    pub signup_at: Option<i64>,

    #[serde(default)]
    pub is_migrated: bool,
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, ToSchema)]
pub struct UserMetadataV2 {
    #[schema(value_type = String)]
    pub user_principal: Principal,
    #[schema(value_type = String)]
    pub user_canister_id: Principal,
    pub user_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_key: Option<NotificationKey>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub signup_at: Option<i64>,
    #[serde(default)]
    pub is_migrated: bool,
}

impl UserMetadataV2 {
    pub fn from_metadata(user_principal: Principal, metadata: UserMetadata) -> Self {
        UserMetadataV2 {
            user_principal,
            user_name: metadata.user_name,
            user_canister_id: metadata.user_canister_id,
            notification_key: metadata.notification_key,
            is_migrated: metadata.is_migrated,
            signup_at: metadata.signup_at,
            email: metadata.email,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserMetadataByUsername {
    pub user_principal: Principal,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, ToSchema)]
pub struct SetUserMetadataReqMetadata {
    #[schema(value_type = String)]
    pub user_canister_id: Principal,
    pub user_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, ToSchema)]
pub struct SetUserEmailMetadataReq {
    #[schema(value_type = String)]
    pub email: String,
    pub already_signed_in: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, ToSchema)]
pub struct SetUserSignedInMetadataReq {
    #[schema(value_type = bool)]
    pub already_signed_in: bool,
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, ToSchema)]
pub struct SetUserMetadataReq {
    pub metadata: SetUserMetadataReqMetadata,
    #[schema(value_type = String)]
    pub signature: Signature,
}

pub type SetUserMetadataRes = ();
pub type SetUserEmailMetadataRes = ();

pub type GetUserMetadataRes = Option<UserMetadata>;
pub type GetUserMetadataV2Res = Option<UserMetadataV2>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, ToSchema)]
pub struct BulkUsers {
    #[schema(value_type = Vec<String>)]
    pub users: Vec<Principal>,
}

pub type DeleteMetadataBulkRes = ();

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, ToSchema)]
pub struct BulkGetUserMetadataReq {
    #[schema(value_type = Vec<String>)]
    pub users: Vec<Principal>,
}

pub type BulkGetUserMetadataRes = HashMap<Principal, GetUserMetadataRes>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, ToSchema)]
pub struct CanisterToPrincipalReq {
    #[schema(value_type = Vec<String>)]
    pub canisters: Vec<Principal>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, ToSchema)]
pub struct CanisterToPrincipalRes {
    #[schema(value_type = HashMap<String, String>)]
    pub mappings: HashMap<Principal, Principal>,
}

#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub struct RegisterDeviceReq {
    pub registration_token: DeviceRegistrationToken,
    #[schema(value_type = String)]
    pub signature: Signature,
}

pub type RegisterDeviceRes = ();

#[derive(Serialize, Deserialize, Clone, ToSchema)]
pub struct UnregisterDeviceReq {
    pub registration_token: DeviceRegistrationToken,
    #[schema(value_type = String)]
    pub signature: Signature,
}

pub type UnregisterDeviceRes = ();

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema, Default)]
pub struct NotificationPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema, Debug, Default)]
pub struct SendNotificationReq {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification: Option<NotificationPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub android: Option<AndroidConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webpush: Option<WebpushConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apns: Option<ApnsConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fcm_options: Option<FcmOptions>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema, Default)]
pub struct FcmOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analytics_label: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema, Default)]
pub struct ApnsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fcm_options: Option<ApnsFcmOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_activity_token: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema, Default)]
pub struct ApnsFcmOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analytics_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Eq, ToSchema, Default)]
pub struct AndroidConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collapse_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<AndroidMessagePriority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restricted_package_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification: Option<AndroidNotification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fcm_options: Option<AndroidFcmOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_boot_ok: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema, Default)]
pub struct WebpushConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fcm_options: Option<WebpushFcmOptions>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema, Default)]
pub struct WebpushFcmOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analytics_label: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema, Default)]
pub struct AndroidFcmOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analytics_label: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema)]
pub enum AndroidMessagePriority {
    Normal,
    High,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, ToSchema, Eq, Default)]
pub struct LightSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub light_on_duration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub light_off_duration: Option<String>,
}
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AndroidProxy {
    ProxyUnspecified,
    Allow,
    Deny,
    IfPriorityLowered,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Eq, ToSchema, Default)]
pub struct AndroidNotification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sound: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub click_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_loc_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_loc_args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_loc_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_loc_args: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sticky: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_priority: Option<NotificationPriority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_sound: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_vibrate_timings: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_light_settings: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vibrate_timings: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<AndroidVisibility>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub light_settings: Option<LightSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<AndroidProxy>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AndroidVisibility {
    VisibilityUnspecified,
    Private,
    Public,
    Secret,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationPriority {
    PriorityUnspecified,
    PriorityMin,
    PriorityLow,
    PriorityDefault,
    PriorityHigh,
    PriorityMax,
}

pub type SendNotificationRes = ();

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema, Debug)]
pub struct CanisterSessionRegisteredRes {
    pub success: bool,
    pub error: Option<String>,
    pub referral_success: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, ToSchema, Debug)]
pub struct PopulateIndexResponse {
    pub total: usize,
    pub processed: usize,
    pub failed: usize,
}
