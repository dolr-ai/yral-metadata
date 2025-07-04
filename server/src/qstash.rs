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
pub struct QStashVerifier {
    current_signing_key: String,
    next_signing_key: String,
}

impl QStashVerifier {
    pub fn new(current_signing_key: &str, next_signing_key: &str) -> Result<Self> {
        // Validate that keys are valid base64
        DecodingKey::from_base64_secret(current_signing_key)
            .map_err(|_| Error::Unknown("Invalid current QStash signing key".to_string()))?;
        DecodingKey::from_base64_secret(next_signing_key)
            .map_err(|_| Error::Unknown("Invalid next QStash signing key".to_string()))?;
        
        Ok(Self {
            current_signing_key: current_signing_key.to_string(),
            next_signing_key: next_signing_key.to_string(),
        })
    }
    
    pub async fn verify_request(
        &self,
        req: &web::HttpRequest,
        body: &[u8],
    ) -> Result<QStashClaims> {
        // Extract signature from header
        let signature = req
            .headers()
            .get("Upstash-Signature")
            .ok_or(Error::AuthTokenMissing)?
            .to_str()
            .map_err(|_| Error::AuthTokenInvalid)?;
        
        // Decode header to check algorithm
        let header = decode_header(signature)
            .map_err(|_| Error::AuthTokenInvalid)?;
        
        if header.alg != Algorithm::HS256 {
            return Err(Error::AuthTokenInvalid);
        }
        
        // Create validation
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["Upstash"]);
        validation.validate_exp = true;
        
        // Create decoding keys
        let current_key = DecodingKey::from_base64_secret(&self.current_signing_key)
            .map_err(|_| Error::Unknown("Invalid current key".to_string()))?;
        let next_key = DecodingKey::from_base64_secret(&self.next_signing_key)
            .map_err(|_| Error::Unknown("Invalid next key".to_string()))?;
        
        // Try current key first, then next key
        let token_data = decode::<QStashClaims>(signature, &current_key, &validation)
            .or_else(|_| decode::<QStashClaims>(signature, &next_key, &validation))
            .map_err(|_| Error::AuthTokenInvalid)?;
        
        // Verify body hash
        let expected_body_hash = URL_SAFE
            .decode(&token_data.claims.body)
            .map_err(|_| Error::AuthTokenInvalid)?;
        
        let actual_body_hash = Sha256::digest(body);
        
        if expected_body_hash != actual_body_hash.as_slice() {
            return Err(Error::AuthTokenInvalid);
        }
        
        Ok(token_data.claims)
    }
}