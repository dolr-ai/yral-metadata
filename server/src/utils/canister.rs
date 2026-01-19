use ic_agent::{export::Principal, Agent};
use redis::AsyncCommands;
use yral_canisters_client::{
    ic::PLATFORM_ORCHESTRATOR_ID, platform_orchestrator::PlatformOrchestrator,
    user_index::UserIndex,
};

use crate::{
    dragonfly::{format_to_dragonfly_key, DragonflyPool, YRAL_METADATA_KEY_PREFIX},
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

/// Optimized with pipelines for batch writes to both Redis and Dragonfly
pub async fn populate_canister_to_principal_index(
    agent: &Agent,
    redis_pool: &RedisPool,
    dragonfly_pool: &DragonflyPool,
) -> Result<(usize, usize)> {
    let user_principal_canister_list = get_user_principal_canister_list_v2(agent).await?;

    let total = user_principal_canister_list.len();
    let mut processed = 0;
    let mut failed = 0;

    // Process in batches of 1000
    let batch_size = 1000;
    let mut conn = redis_pool.get().await?;
    let mut dragonfly_conn = dragonfly_pool.get().await?;

    let dragonfly_key =
        format_to_dragonfly_key(YRAL_METADATA_KEY_PREFIX, CANISTER_TO_PRINCIPAL_KEY);

    for batch in user_principal_canister_list.chunks(batch_size) {
        // Convert to format needed for Redis
        let items: Vec<(String, String)> = batch
            .iter()
            .map(|(user_principal, canister_id)| (canister_id.to_text(), user_principal.to_text()))
            .collect();

        // Use pipeline for Redis bulk insertion
        let mut redis_pipe = redis::pipe();
        for (canister_id, user_principal) in &items {
            redis_pipe.hset(CANISTER_TO_PRINCIPAL_KEY, canister_id, user_principal);
        }

        match redis_pipe.query_async::<()>(&mut *conn).await {
            Ok(_) => {
                processed += batch.len();
            }
            Err(e) => {
                log::error!("Failed to insert batch to Redis: {}", e);
                failed += batch.len();
            }
        }

        // Use pipeline for Dragonfly bulk insertion
        let mut dragonfly_pipe = redis::pipe();
        for (canister_id, user_principal) in &items {
            dragonfly_pipe.hset(&dragonfly_key, canister_id, user_principal);
        }

        if let Err(e) = dragonfly_pipe.query_async::<()>(&mut dragonfly_conn).await {
            log::error!("Failed to insert batch into Dragonfly: {}", e);
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
