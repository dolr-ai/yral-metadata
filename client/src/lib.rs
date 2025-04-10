pub mod consts;
mod error;

pub use error::*;

use consts::DEFAULT_API_URL;

use ic_agent::{export::Principal, Identity};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION},
    Url,
};
use types::{
    ApiResult, BulkUsers, GetUserMetadataRes, SetUserMetadataReq, SetUserMetadataRes, UserMetadata,
};
use yral_identity::ic_agent::sign_message;

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
        metadata: UserMetadata,
    ) -> Result<SetUserMetadataRes> {
        let signature = sign_message(identity, metadata.clone().into())?;
        // unwrap safety: we know the sender is present because we just signed the message
        let sender = identity.sender().unwrap();
        let api_url = self
            .base_url
            .join("metadata/")
            .unwrap()
            .join(&sender.to_text())
            .unwrap();

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

    pub async fn get_user_metadata(&self, user_principal: Principal) -> Result<GetUserMetadataRes> {
        let api_url = self
            .base_url
            .join("metadata/")
            .unwrap()
            .join(&user_principal.to_text())
            .unwrap();

        let res = self.client.get(api_url).send().await?;

        let res: ApiResult<GetUserMetadataRes> = res.json().await?;
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
        let api_url = self.base_url.join("metadata/bulk").unwrap();

        let jwt_token = self.jwt_token.as_ref().expect("jwt token not set");
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(jwt_token).unwrap());

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
