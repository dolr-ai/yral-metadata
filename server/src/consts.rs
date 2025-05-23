use once_cell::sync::Lazy;

use crate::auth::Claims;

pub static CLAIMS: Lazy<Claims> = Lazy::new(|| Claims {
    sub: "off-chain-agent".to_string(),
    company: "gobazzinga".to_string(),
    exp: 317125598072, // TODO: To be changed later when expiring tokens periodically
});

pub const YRAL_AUTH_V2_ACCESS_TOKEN_ISS: &str = "https://auth.yral.com";
