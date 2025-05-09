use std::net::SocketAddr;

use config::{Config, ConfigError, Environment, File};
use redis::ConnectionInfo;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Deserialize)]
pub struct AppConfig {
    pub bind_address: SocketAddr,
    #[serde_as(as = "DisplayFromStr")]
    pub redis_url: ConnectionInfo,
    pub jwt_public_key: String,
    pub yral_auth_public_key: String,
    #[serde(alias = "yral_app_admin_dfx_identity_private_key")]
    pub backend_admin_identity: String,
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let conf = Config::builder()
            .add_source(File::with_name("config.toml").required(false))
            .add_source(File::with_name(".env").required(false))
            .add_source(Environment::default())
            .build()?;

        conf.try_deserialize()
    }
}
