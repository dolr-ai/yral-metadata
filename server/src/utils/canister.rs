use ic_agent::Agent;

use crate::{
    dragonfly::DragonflyPool,
    utils::error::Result,
};

pub const CANISTER_TO_PRINCIPAL_KEY: &str = "canister2principal";

/// Subnet orchestrators (user_index canisters) have been decommissioned.
/// This function now returns an empty list. Callers that need user canister
/// mappings should use user_info_service instead.
pub async fn get_user_principal_canister_list_v2(
    _agent: &Agent,
) -> Result<Vec<(candid::Principal, candid::Principal)>> {
    Ok(vec![])
}

/// Optimized with pipelines for batch writes to both Redis and Dragonfly
///
/// Subnet orchestrators have been decommissioned, so this is now a no-op that
/// returns (0, 0). Kept for API compatibility with the admin endpoint.
pub async fn populate_canister_to_principal_index(
    _agent: &Agent,
    _dragonfly_redis_store: &DragonflyPool,
) -> Result<(usize, usize)> {
    Ok((0, 0))
}
