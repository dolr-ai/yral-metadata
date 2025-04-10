use std::env;

use hyper_util::client::legacy::connect::HttpConnector;
use yup_oauth2::hyper_rustls::HttpsConnector;
use yup_oauth2::{authenticator::Authenticator, ServiceAccountAuthenticator};

pub mod notifications;

#[derive(Clone)]
pub struct Firebase {
    auth: Authenticator<HttpsConnector<HttpConnector>>,
}

pub async fn init_auth() -> Authenticator<HttpsConnector<HttpConnector>> {
    let sa_key_file = env::var("GOOGLE_SA_KEY").expect("GOOGLE_SA_KEY is required");

    // Load your service account key
    let sa_key = yup_oauth2::parse_service_account_key(sa_key_file).expect("GOOGLE_SA_KEY.json");

    ServiceAccountAuthenticator::builder(sa_key)
        .build()
        .await
        .unwrap()
}

impl Firebase {
    pub async fn new() -> Self {
        let auth = init_auth().await;
        Self { auth }
    }

    async fn get_access_token(&self, scopes: &[&str]) -> String {
        let auth = &self.auth;
        let token = auth.token(scopes).await.unwrap();

        match token.token() {
            Some(t) => t.to_string(),
            _ => panic!("No access token found"),
        }
    }
}
