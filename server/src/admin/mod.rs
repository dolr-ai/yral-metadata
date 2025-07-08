use ntex::util::Bytes;
use ntex::web;
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use crate::utils::canister::populate_canister_to_principal_index;
use crate::utils::error::Result;
use types::PopulateIndexResponse;

#[derive(Debug, Serialize, Deserialize)]
pub struct QStashRequest {
    // QStash sends various fields, but we only need to verify the signature
    #[serde(flatten)]
    pub data: serde_json::Value,
}

#[web::post("/admin/populate-canister-index")]
pub async fn populate_canister_index(
    state: web::types::State<AppState>,
    req: web::HttpRequest,
    body: Bytes,
) -> Result<web::HttpResponse> {
    // Verify QStash signature
    state.qstash.verify_qstash_message(&req, &body).await?;

    // Call the populate function
    let (total, processed) =
        populate_canister_to_principal_index(&state.backend_admin_ic_agent, &state.redis).await?;

    let response = PopulateIndexResponse {
        total,
        processed,
        failed: total - processed,
    };

    Ok(web::HttpResponse::Ok().json(&response))
}
