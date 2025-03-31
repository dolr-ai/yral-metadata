use crate::auth::JwtDetails;

use crate::auth::init_jwt;
use crate::config::AppConfig;
use hyper_util::client::legacy::connect::HttpConnector;
use std::env;
use yup_oauth2::hyper_rustls::HttpsConnector;
use yup_oauth2::{authenticator::Authenticator, ServiceAccountAuthenticator};

pub type RedisPool = bb8::Pool<bb8_redis::RedisConnectionManager>;

#[derive(Clone)]
pub struct AppState {
    pub redis: RedisPool,
    pub jwt_details: JwtDetails,
    pub auth: Authenticator<HttpsConnector<HttpConnector>>,
}

impl AppState {
    pub async fn new(app_config: &AppConfig) -> Self {
        AppState {
            redis: init_redis(app_config).await,
            jwt_details: init_jwt(app_config),
            auth: init_auth().await,
        }
    }

    pub async fn get_access_token(&self, scopes: &[&str]) -> String {
        let auth = &self.auth;
        let token = auth.token(scopes).await.unwrap();

        match token.token() {
            Some(t) => t.to_string(),
            _ => panic!("No access token found"),
        }
    }
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

pub async fn init_redis(conf: &AppConfig) -> RedisPool {
    let manager = bb8_redis::RedisConnectionManager::new(conf.redis_url.clone())
        .expect("failed to open connection to redis");
    RedisPool::builder().build(manager).await.unwrap()
}
