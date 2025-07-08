pub mod consts;
mod error;

pub use error::*;

use consts::DEFAULT_API_URL;

use ic_agent::{export::Principal, Identity};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION},
    Url,
};
use std::collections::HashMap;
use types::{
    ApiResult, BulkGetUserMetadataReq, BulkGetUserMetadataRes, BulkUsers, CanisterToPrincipalReq, CanisterToPrincipalRes, GetUserMetadataRes, GetUserMetadataV2Res, RegisterDeviceReq, RegisterDeviceRes, SetUserMetadataReq, SetUserMetadataReqMetadata, SetUserMetadataRes, UnregisterDeviceReq, UnregisterDeviceRes
};
use yral_identity::ic_agent::sign_message;

pub use types::{DeviceRegistrationToken, NotificationKey};

#[derive(Clone, Debug)]
pub struct MetadataClient<const AUTH: bool> {
    base_url: Url,
    client: reqwest::Client,
    jwt_token: Option<String>,
}

impl Default for MetadataClient<false> {
    fn default() -> Self {
        Self {
            base_url: Url::parse(DEFAULT_API_URL).unwrap(),
            client: Default::default(),
            jwt_token: None,
        }
    }
}

impl<const A: bool> MetadataClient<A> {
    pub fn with_base_url(base_url: Url) -> Self {
        Self {
            base_url,
            client: Default::default(),
            jwt_token: None,
        }
    }

    pub async fn set_user_metadata(
        &self,
        identity: &impl Identity,
        metadata: SetUserMetadataReqMetadata,
    ) -> Result<SetUserMetadataRes> {
        let signature = sign_message(
            identity,
            metadata
                .clone()
                .try_into()
                .map_err(|_| Error::Api(types::error::ApiError::MetadataNotFound))?,
        )?;
        let sender = identity
            .sender()
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?;
        let api_url = self
            .base_url
            .join("metadata/")
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?
            .join(&sender.to_text())
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?;

        let res = self
            .client
            .post(api_url)
            .json(&SetUserMetadataReq {
                metadata,
                signature,
            })
            .send()
            .await?;

        let res: ApiResult<SetUserMetadataRes> = res.json().await?;
        Ok(res?)
    }

    async fn get_user_metadata_inner(
        &self,
        username_or_principal: String,
    ) -> Result<GetUserMetadataV2Res> {
        let api_url = self
            .base_url
            .join("metadata/")
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?
            .join(&&username_or_principal)
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?;

        let res = self.client.get(api_url).send().await?;

        let res: ApiResult<GetUserMetadataV2Res> = res.json().await?;
        Ok(res?)
    }

    #[deprecated(note = "Use `get_user_metadata_v2` instead")]
    pub async fn get_user_metadata(&self, user_principal: Principal) -> Result<GetUserMetadataV2Res> {
        self.get_user_metadata_inner(user_principal.to_text())
            .await
    }

    pub async fn get_user_metadata_v2(&self, username_or_principal: String) -> Result<GetUserMetadataV2Res> {
        self.get_user_metadata_inner(username_or_principal)
            .await
    }

    pub async fn get_user_metadata_bulk(
        &self,
        user_principals: Vec<Principal>,
    ) -> Result<HashMap<Principal, GetUserMetadataRes>> {
        let api_url = self
            .base_url
            .join("metadata-bulk")
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?;

        let res = self
            .client
            .post(api_url)
            .json(&BulkGetUserMetadataReq {
                users: user_principals,
            })
            .send()
            .await?;

        let res: ApiResult<BulkGetUserMetadataRes> = res.json().await?;
        Ok(res?)
    }

    pub async fn get_canister_to_principal_bulk(
        &self,
        canisters: Vec<Principal>,
    ) -> Result<HashMap<Principal, Principal>> {
        let api_url = self
            .base_url
            .join("canister-to-principal/bulk")
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?;

        let res = self
            .client
            .post(api_url)
            .json(&CanisterToPrincipalReq { canisters })
            .send()
            .await?;

        let res: ApiResult<CanisterToPrincipalRes> = res.json().await?;
        Ok(res?.mappings)
    }

    pub async fn register_device(
        &self,
        identity: &impl Identity,
        registration_token: DeviceRegistrationToken,
    ) -> Result<RegisterDeviceRes> {
        let signature = sign_message(
            identity,
            registration_token
                .clone()
                .try_into()
                .map_err(|_| Error::Api(types::error::ApiError::AuthTokenMissing))?,
        )?;
        let sender = identity
            .sender()
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?;

        let api_url = self
            .base_url
            .join("notifications/")
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?
            .join(&sender.to_text())
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?;

        let res = self
            .client
            .post(api_url)
            .json(&RegisterDeviceReq {
                registration_token,
                signature,
            })
            .send()
            .await?;

        let res: ApiResult<RegisterDeviceRes> = res.json().await?;
        Ok(res?)
    }

    pub async fn unregister_device(
        &self,
        identity: &impl Identity,
        registration_token: DeviceRegistrationToken,
    ) -> Result<UnregisterDeviceRes> {
        let signature = sign_message(
            identity,
            registration_token
                .clone()
                .try_into()
                .map_err(|_| Error::Api(types::error::ApiError::AuthTokenMissing))?,
        )?;
        let sender = identity
            .sender()
            .map_err(|_| Error::Identity(yral_identity::Error::SenderNotFound))?;
        let api_url = self
            .base_url
            .join("notifications/")
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?
            .join(&sender.to_text())
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?;

        let res = self
            .client
            .delete(api_url)
            .json(&UnregisterDeviceReq {
                registration_token,
                signature,
            })
            .send()
            .await?;

        let res: ApiResult<UnregisterDeviceRes> = res.json().await?;
        Ok(res?)
    }
}

impl MetadataClient<true> {
    pub fn with_jwt_token(self, jwt_token: String) -> Self {
        Self {
            jwt_token: Some(jwt_token),
            ..self
        }
    }

    pub async fn delete_metadata_bulk(&self, users: Vec<Principal>) -> Result<()> {
        let api_url = self
            .base_url
            .join("metadata/bulk")
            .map_err(|e| Error::Api(types::error::ApiError::Unknown(e.to_string())))?;

        let jwt_token = self
            .jwt_token
            .as_ref()
            .ok_or(Error::Api(types::error::ApiError::Jwt))?;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(jwt_token)
                .map_err(|_| Error::Api(types::error::ApiError::Jwt))?,
        );

        let body = BulkUsers { users };

        let res = self
            .client
            .delete(api_url)
            .json(&body)
            .headers(headers)
            .send()
            .await?;

        let res: ApiResult<()> = res.json().await?;
        Ok(res?)
    }
}
