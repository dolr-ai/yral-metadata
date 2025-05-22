use jsonwebtoken::DecodingKey;
use serde::{Deserialize, Serialize};

use crate::consts::YRAL_AUTH_V2_ACCESS_TOKEN_ISS;

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
        let decoding_key = DecodingKey::from_ec_pem(public_key.as_bytes())?;

        Ok(YralAuthJwt { decoding_key })
    }

    pub fn verify_token(&self, token: &str) -> Result<YralAuthClaim, Error> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&[YRAL_AUTH_V2_ACCESS_TOKEN_ISS]);

        let token_message =
            jsonwebtoken::decode::<YralAuthClaim>(token, &self.decoding_key, &validation)
                .map_err(Error::Jwt)?;

        if token_message.claims.ext_is_anonymous {
            return Err(Error::AuthTokenInvalid);
        }

        Ok(token_message.claims)
    }
}
