pub mod store;

use candid::Principal;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use types::error::ApiError;

#[derive(Debug, Deserialize)]
struct InquiryData {
    data: Inquiry,
}

#[derive(Debug, Deserialize)]
struct Inquiry {
    attributes: InquiryAttributes,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct InquiryAttributes {
    status: String,
    #[serde(rename = "reference-id")]
    reference_id: Option<String>,
}

pub struct KycService;

impl KycService {
    pub async fn check_kyc_completed(
        user_principal: Principal,
        inquiry_id: String,
    ) -> Result<(), ApiError> {
        let token =
            std::env::var("KYC_SERVER_TOKEN").map_err(|e| ApiError::EnvironmentVariableMissing)?;
        let url = format!("https://api.withpersona.com/api/v1/inquiries/{inquiry_id}",);

        let client = reqwest::Client::new();
        let res = client
            .get(&url)
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await
            .map_err(|f| ApiError::ReqwestError(f.to_string()))?;

        if !res.status().is_success() {
            return Err(ApiError::KycApiError(format!(
                "Failed to fetch inquiry: {}",
                res.status()
            )));
        }

        let data: InquiryData = res
            .json()
            .await
            .map_err(|e| ApiError::KycApiError(e.to_string()))?;

        let status = data.data.attributes.status.to_lowercase();

        let res_reference_id = data.data.attributes.reference_id;
        if (status == "approved" || status == "completed") && res_reference_id == Some(user_principal.to_text()) {
            Ok(())
        } else {
            Err(ApiError::KycApiError(format!(
                "KYC not completed, current status: {}",
                status
            )))
        }
    }
}
