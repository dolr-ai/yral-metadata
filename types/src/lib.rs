pub mod error;
use candid::Principal;
use error::ApiError;
use serde::{Deserialize, Serialize};
use yral_identity::{msg_builder::Message, Signature};

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserMetadata {
    pub user_canister_id: Principal,
    pub user_name: String,
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

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct SetUserMetadataReq {
    pub metadata: UserMetadata,
    pub signature: Signature,
}

pub type SetUserMetadataRes = ();

pub type GetUserMetadataRes = Option<UserMetadata>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct BulkUsers {
    pub users: Vec<Principal>,
}

pub type DeleteMetadataBulkRes = ();
