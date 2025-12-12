use axum::{body::Bytes, extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use types::PopulateIndexResponse;

use crate::state::AppState;
use crate::utils::canister::populate_canister_to_principal_index;
use crate::utils::error::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct QStashRequest {
    // QStash sends various fields, but we only need to verify the signature
    #[serde(flatten)]
    pub data: serde_json::Value,
}

pub async fn populate_canister_index(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PopulateIndexResponse>> {
    // Verify QStash signature
    state.qstash.verify_qstash_message(&headers, &body).await?;

    // Call the populate function
    let (total, processed) =
        populate_canister_to_principal_index(&state.backend_admin_ic_agent, &state.redis).await?;

    let response = PopulateIndexResponse {
        total,
        processed,
        failed: total - processed,
    };

    Ok(Json(response))
}
