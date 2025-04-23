use std::env;

use hyper_rustls::{self, HttpsConnector};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use yral_identity::Result;
use yup_oauth2::{
    authenticator::Authenticator, CustomHyperClientBuilder, ServiceAccountAuthenticator,
};

use crate::error::Error;

pub mod notifications;

#[derive(Clone)]
pub struct Firebase {
    auth: Authenticator<HttpsConnector<HttpConnector>>,
}

pub async fn init_auth() -> Result<Authenticator<HttpsConnector<HttpConnector>>, Error> {
    let sa_key_file = env::var("CLIENT_NOTIFICATIONS_GOOGLE_SERVICE_ACCOUNT_KEY")
        .map_err(|e| Error::Unknown(e.to_string()))?;

    // Load your service account key
    let sa_key = yup_oauth2::parse_service_account_key(sa_key_file)
        .map_err(|e| Error::Unknown(e.to_string()))?;

    // Make sure the crypto provider is installed (see https://github.com/rustls/rustls/issues/1938)
    let _ = rustls::crypto::ring::default_provider().install_default();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_all_versions()
        .build();
    let client = Client::builder(hyper_util::rt::TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build::<_, String>(connector);

    let client_builder = CustomHyperClientBuilder::from(client);
    let authenticator = ServiceAccountAuthenticator::with_client(sa_key, client_builder)
        .build()
        .await
        .map_err(|e| Error::Unknown(e.to_string()))?;

    Ok(authenticator)
}

impl Firebase {
    pub async fn new() -> Result<Self, Error> {
        let auth = init_auth().await?;
        Ok(Self { auth })
    }

    async fn get_access_token(&self, scopes: &[&str]) -> Result<String, Error> {
        let auth = &self.auth;
        let token = auth
            .token(scopes)
            .await
            .map_err(|_| Error::AuthTokenInvalid)?;

        match token.token() {
            Some(t) => Ok(t.to_string()),
            _ => Err(Error::AuthTokenMissing),
        }
    }
}
