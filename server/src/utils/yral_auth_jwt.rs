use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::DecodingKey;
use ntex::time;
use serde::{Deserialize, Serialize};

use super::error::Error;

#[derive(Serialize, Deserialize)]
pub struct YralAuthClaim {
    aud: String,
    exp: u64,
    iat: u64,
    iss: String,
    pub sub: String,
    nonce: Option<String>,
    ext_is_anonymous: bool,
}
#[derive(Clone)]
pub struct YralAuthJwt {
    pub decoding_key: DecodingKey,
}

impl YralAuthJwt {
    pub fn init(public_key: String) -> Result<Self, Error> {
        let decoding_key = DecodingKey::from_ed_pem(public_key.as_bytes())?;

        Ok(YralAuthJwt { decoding_key })
    }

    pub fn verify_token(&self, token: &str) -> Result<YralAuthClaim, Error> {
        let token_message = jsonwebtoken::decode::<YralAuthClaim>(
            token,
            &self.decoding_key,
            &jsonwebtoken::Validation::default(),
        )
        .map_err(Error::Jwt)?;

        let expiry = token_message.claims.exp;

        // Check if the token is expired
        if expiry
            < SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs()
        {
            return Err(Error::AuthTokenInvalid);
        }

        if token_message.claims.ext_is_anonymous {
            return Err(Error::AuthTokenInvalid);
        }

        Ok(token_message.claims)
    }
}
