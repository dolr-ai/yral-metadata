use ic_agent::{export::Principal, Agent};
use redis::AsyncCommands;
use yral_canisters_client::{
    ic::PLATFORM_ORCHESTRATOR_ID, platform_orchestrator::PlatformOrchestrator, user_index::UserIndex
};

use crate::{
    state::RedisPool,
    utils::error::{Error, Result},
};

pub const CANISTER_TO_PRINCIPAL_KEY: &str = "canister2principal";

pub async fn get_subnet_orch_ids(agent: &Agent) -> Result<Vec<Principal>> {
    let pf_orch = PlatformOrchestrator(PLATFORM_ORCHESTRATOR_ID, agent);

    let subnet_orch_ids = pf_orch
        .get_all_subnet_orchestrators()
        .await
        .map_err(|e| Error::Unknown(format!("Failed to get subnet orchestrators: {}", e)))?;

    Ok(subnet_orch_ids)
}

pub async fn get_user_canisters_list_v2(agent: &Agent) -> Result<Vec<Principal>> {
    let subnet_orch_ids = get_subnet_orch_ids(agent).await?;

    let mut canister_ids_list = vec![];

    for subnet_orch_id in subnet_orch_ids {
        let subnet_orch = UserIndex(subnet_orch_id, agent);
        let user_canister_ids = subnet_orch
            .get_user_canister_list()
            .await
            .map_err(|e| Error::Unknown(format!("Failed to get user canister list: {}", e)))?;
        canister_ids_list.extend(user_canister_ids);
    }

    Ok(canister_ids_list)
}

pub async fn get_user_principal_canister_list_v2(
    agent: &Agent,
) -> Result<Vec<(Principal, Principal)>> {
    let subnet_orch_ids = get_subnet_orch_ids(agent).await?;

    let mut user_principal_canister_list = vec![];

    for subnet_orch_id in subnet_orch_ids {
        let subnet_orch = UserIndex(subnet_orch_id, agent);
        let user_principal_canister_ids = subnet_orch
            .get_user_id_and_canister_list()
            .await
            .map_err(|e| {
                Error::Unknown(format!("Failed to get user id and canister list: {}", e))
            })?;
        user_principal_canister_list.extend(user_principal_canister_ids);
    }

    Ok(user_principal_canister_list)
}

pub async fn populate_canister_to_principal_index(
    agent: &Agent,
    redis_pool: &RedisPool,
) -> Result<(usize, usize)> {
    let user_principal_canister_list = get_user_principal_canister_list_v2(agent).await?;

    let total = user_principal_canister_list.len();
    let mut processed = 0;
    let mut failed = 0;

    // Process in batches of 1000
    let batch_size = 1000;

    for batch in user_principal_canister_list.chunks(batch_size) {
        // Convert to format needed for Redis
        let items: Vec<(String, String)> = batch
            .iter()
            .map(|(user_principal, canister_id)| (canister_id.to_text(), user_principal.to_text()))
            .collect();

        // Get Redis connection
        let mut conn = redis_pool.get().await?;

        // Use hset_multiple for efficient bulk insertion
        match conn
            .hset_multiple::<_, _, _, ()>(CANISTER_TO_PRINCIPAL_KEY, &items)
            .await
        {
            Ok(_) => {
                processed += batch.len();
            }
            Err(e) => {
                log::error!("Failed to insert batch: {}", e);
                failed += batch.len();
            }
        }
    }

    log::info!(
        "Canister to principal index population complete: {} processed, {} failed out of {} total",
        processed,
        failed,
        total
    );

    Ok((processed, failed))
}
