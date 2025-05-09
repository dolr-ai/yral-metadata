use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::{config::AppConfig, consts::CLAIMS, utils::error::Error};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    pub sub: String,
    pub company: String,
    pub exp: u64,
}

#[derive(Clone)]
pub struct JwtDetails {
    pub decoding_key: DecodingKey,
    pub validation: Validation,
}

pub fn init_jwt(conf: &AppConfig) -> Result<JwtDetails, Error> {
    let decoding_key = DecodingKey::from_ed_pem(conf.jwt_public_key.as_bytes())?;

    let validation = Validation::new(Algorithm::EdDSA);

    Ok(JwtDetails {
        decoding_key,
        validation,
    })
}

pub fn verify_token(token: &str, jwt_details: &JwtDetails) -> Result<(), Error> {
    let JwtDetails {
        decoding_key,
        validation,
    } = jwt_details;

    let token_message = decode::<Claims>(token, decoding_key, validation).map_err(Error::Jwt)?;

    if token_message.claims != *CLAIMS {
        return Err(Error::AuthTokenInvalid);
    }

    Ok(())
}
