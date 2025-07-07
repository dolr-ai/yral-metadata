use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use ntex::web;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::utils::error::{Error, Result};

#[derive(Debug, Serialize, Deserialize)]
pub struct QStashClaims {
    pub iss: String,
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub nbf: isize,
    pub jti: String,
    pub body: String,
}

#[derive(Clone)]
pub struct QStashState {
    decoding_key: Arc<DecodingKey>,
    validation: Arc<Validation>,
}

impl QStashState {
    pub fn init(verification_key: String) -> Self {
        let decoding_key = DecodingKey::from_secret(verification_key.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["Upstash"]);
        validation.set_audience(&[""]);
        Self {
            decoding_key: Arc::new(decoding_key),
            validation: Arc::new(validation),
        }
    }

    pub async fn verify_qstash_message(&self, req: &web::HttpRequest, body: &[u8]) -> Result<()> {
        let signature = req
            .headers()
            .get("Upstash-Signature")
            .ok_or(Error::AuthTokenMissing)?
            .to_str()
            .map_err(|_| Error::AuthTokenInvalid)?;

        let jwt =
            jsonwebtoken::decode::<QStashClaims>(signature, &self.decoding_key, &self.validation)
                .map_err(|_| Error::AuthTokenInvalid)?;

        let sig_body_hash = URL_SAFE
            .decode(jwt.claims.body)
            .map_err(|_| Error::AuthTokenInvalid)?;

        let derived_hash = Sha256::digest(&body);

        if derived_hash.as_slice() != sig_body_hash.as_slice() {
            return Err(Error::AuthTokenInvalid);
        }

        Ok(())
    }
}
