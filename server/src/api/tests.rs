use super::implementation::*;
use crate::test_utils::test_helpers::*;
use crate::utils::canister::CANISTER_TO_PRINCIPAL_KEY;
use candid::Principal;
use redis::AsyncCommands;
use types::{BulkGetUserMetadataReq, BulkUsers, CanisterToPrincipalReq};

#[tokio::test]
async fn test_set_user_metadata_valid_request() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    let user_principal = generate_test_principal(1);
    let metadata = create_test_metadata_req(100, "test_user");
    
    // Execute - using core implementation that skips signature verification
    let result = set_user_metadata_core(&redis_pool, user_principal, &metadata).await;
    
    // Verify
    assert!(result.is_ok());
    
    // Check data was stored
    let mut conn = redis_pool.get().await.unwrap();
    let stored: Option<Vec<u8>> = conn.hget(user_principal.to_text(), METADATA_FIELD).await.unwrap();
    assert!(stored.is_some());
    
    // Check reverse index was updated
    let reverse_lookup: Option<String> = conn
        .hget(CANISTER_TO_PRINCIPAL_KEY, generate_test_principal(100).to_text())
        .await
        .unwrap();
    assert_eq!(reverse_lookup, Some(user_principal.to_text()));
    
    // Cleanup
    cleanup_test_data(&redis_pool, &user_principal.to_text()).await.unwrap();
    let _: () = conn.hdel(CANISTER_TO_PRINCIPAL_KEY, generate_test_principal(100).to_text()).await.unwrap();
}

#[tokio::test]
async fn test_set_user_metadata_updates_existing() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    let user_principal = generate_test_principal(2);
    
    // First request
    let metadata1 = create_test_metadata_req(200, "original_name");
    set_user_metadata_core(&redis_pool, user_principal, &metadata1).await.unwrap();
    
    // Second request with updated name
    let metadata2 = create_test_metadata_req(200, "updated_name");
    let result = set_user_metadata_core(&redis_pool, user_principal, &metadata2).await;
    
    // Verify
    assert!(result.is_ok());
    
    // Check updated data
    let mut conn = redis_pool.get().await.unwrap();
    let stored: Option<Vec<u8>> = conn.hget(user_principal.to_text(), METADATA_FIELD).await.unwrap();
    let metadata: types::UserMetadata = serde_json::from_slice(&stored.unwrap()).unwrap();
    assert_eq!(metadata.user_name, "updated_name");
    
    // Cleanup
    cleanup_test_data(&redis_pool, &user_principal.to_text()).await.unwrap();
    let _: () = conn.hdel(CANISTER_TO_PRINCIPAL_KEY, generate_test_principal(200).to_text()).await.unwrap();
}

#[tokio::test]
async fn test_get_user_metadata_existing() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    let user_principal = generate_test_principal(3);
    let test_metadata = create_test_user_metadata(3, 300);
    
    // Store test data
    let mut conn = redis_pool.get().await.unwrap();
    let meta_bytes = serde_json::to_vec(&test_metadata).unwrap();
    let _: () = conn.hset(user_principal.to_text(), METADATA_FIELD, &meta_bytes).await.unwrap();
    
    // Execute
    let result = get_user_metadata_impl(&redis_pool, user_principal).await;
    
    // Verify
    assert!(result.is_ok());
    let metadata = result.unwrap();
    assert!(metadata.is_some());
    let metadata = metadata.unwrap();
    assert_eq!(metadata.user_name, "test_user_3");
    assert_eq!(metadata.user_canister_id, generate_test_principal(300));
    
    // Cleanup
    cleanup_test_data(&redis_pool, &user_principal.to_text()).await.unwrap();
}

#[tokio::test]
async fn test_get_user_metadata_not_found() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    let user_principal = generate_test_principal(4);
    
    // Execute
    let result = get_user_metadata_impl(&redis_pool, user_principal).await;
    
    // Verify
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[tokio::test]
async fn test_delete_metadata_bulk() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    
    // Create test users
    let users = vec![
        generate_test_principal(5),
        generate_test_principal(6),
        generate_test_principal(7),
    ];
    
    // Store test data for each user
    let mut conn = redis_pool.get().await.unwrap();
    for (i, user) in users.iter().enumerate() {
        let metadata = create_test_user_metadata(5 + i as u64, 500 + i as u64);
        let meta_bytes = serde_json::to_vec(&metadata).unwrap();
        let _: () = conn.hset(user.to_text(), METADATA_FIELD, &meta_bytes).await.unwrap();
        let _: () = conn.hset(
            CANISTER_TO_PRINCIPAL_KEY,
            metadata.user_canister_id.to_text(),
            user.to_text()
        ).await.unwrap();
    }
    
    // Execute
    let bulk_users = BulkUsers { users: users.clone() };
    let result = delete_metadata_bulk_impl(&redis_pool, bulk_users).await;
    
    // Verify
    assert!(result.is_ok());
    
    // Check all user data was deleted
    for user in &users {
        let exists: Option<Vec<u8>> = conn.hget(user.to_text(), METADATA_FIELD).await.unwrap();
        assert!(exists.is_none());
    }
    
    // Check reverse index was cleaned up
    for i in 0..3 {
        let canister_id = generate_test_principal(500 + i);
        let exists: Option<String> = conn.hget(CANISTER_TO_PRINCIPAL_KEY, canister_id.to_text()).await.unwrap();
        assert!(exists.is_none());
    }
}


#[tokio::test]
async fn test_delete_metadata_bulk_empty_list() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    
    let bulk_users = BulkUsers { users: vec![] };
    
    // Execute
    let result = delete_metadata_bulk_impl(&redis_pool, bulk_users).await;
    
    // Verify
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_metadata_bulk_large_batch() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    
    // Create 1500 test users (more than chunk size of 1000)
    let users: Vec<Principal> = (0..1500)
        .map(|i| generate_test_principal(1000 + i))
        .collect();
    
    // Store test data
    let mut conn = redis_pool.get().await.unwrap();
    for (i, user) in users.iter().enumerate() {
        let metadata = create_test_user_metadata(1000 + i as u64, 10000 + i as u64);
        let meta_bytes = serde_json::to_vec(&metadata).unwrap();
        let _: () = conn.hset(user.to_text(), METADATA_FIELD, &meta_bytes).await.unwrap();
    }
    
    // Execute
    let bulk_users = BulkUsers { users: users.clone() };
    let result = delete_metadata_bulk_impl(&redis_pool, bulk_users).await;
    
    // Verify
    assert!(result.is_ok());
    
    // Spot check some users were deleted
    for i in (0..1500).step_by(100) {
        let user = generate_test_principal(1000 + i);
        let exists: Option<Vec<u8>> = conn.hget(user.to_text(), METADATA_FIELD).await.unwrap();
        assert!(exists.is_none());
    }
}

#[tokio::test]
async fn test_get_user_metadata_bulk_multiple_users() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    
    // Create test users
    let users = vec![
        generate_test_principal(20),
        generate_test_principal(21),
        generate_test_principal(22),
    ];
    
    // Store test data for some users (not all)
    let mut conn = redis_pool.get().await.unwrap();
    let metadata1 = create_test_user_metadata(20, 2000);
    let meta_bytes1 = serde_json::to_vec(&metadata1).unwrap();
    let _: () = conn.hset(users[0].to_text(), METADATA_FIELD, &meta_bytes1).await.unwrap();
    
    let metadata2 = create_test_user_metadata(22, 2002);
    let meta_bytes2 = serde_json::to_vec(&metadata2).unwrap();
    let _: () = conn.hset(users[2].to_text(), METADATA_FIELD, &meta_bytes2).await.unwrap();
    
    // Execute
    let req = BulkGetUserMetadataReq { users: users.clone() };
    let result = get_user_metadata_bulk_impl(&redis_pool, req).await;
    
    // Verify
    assert!(result.is_ok());
    let results = result.unwrap();
    assert_eq!(results.len(), 3);
    
    // Check specific results
    assert!(results.get(&users[0]).unwrap().is_some());
    assert_eq!(results.get(&users[0]).unwrap().as_ref().unwrap().user_name, "test_user_20");
    
    assert!(results.get(&users[1]).unwrap().is_none());
    
    assert!(results.get(&users[2]).unwrap().is_some());
    assert_eq!(results.get(&users[2]).unwrap().as_ref().unwrap().user_name, "test_user_22");
    
    // Cleanup
    for user in &users {
        cleanup_test_data(&redis_pool, &user.to_text()).await.unwrap();
    }
}

#[tokio::test]
async fn test_get_user_metadata_bulk_empty_request() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    
    // Execute
    let req = BulkGetUserMetadataReq { users: vec![] };
    let result = get_user_metadata_bulk_impl(&redis_pool, req).await;
    
    // Verify
    assert!(result.is_ok());
    let results = result.unwrap();
    assert!(results.is_empty());
}

#[tokio::test]
async fn test_get_user_metadata_bulk_concurrent_processing() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    
    // Create 20 test users to test concurrent processing
    let users: Vec<Principal> = (0..20)
        .map(|i| generate_test_principal(100 + i))
        .collect();
    
    // Store test data
    let mut conn = redis_pool.get().await.unwrap();
    for (i, user) in users.iter().enumerate() {
        let metadata = create_test_user_metadata(100 + i as u64, 1000 + i as u64);
        let meta_bytes = serde_json::to_vec(&metadata).unwrap();
        let _: () = conn.hset(user.to_text(), METADATA_FIELD, &meta_bytes).await.unwrap();
    }
    
    // Execute
    let req = BulkGetUserMetadataReq { users: users.clone() };
    let result = get_user_metadata_bulk_impl(&redis_pool, req).await;
    
    // Verify
    assert!(result.is_ok());
    let results = result.unwrap();
    assert_eq!(results.len(), 20);
    
    // All users should have metadata
    for user in &users {
        assert!(results.get(user).unwrap().is_some());
    }
    
    // Cleanup
    for user in &users {
        cleanup_test_data(&redis_pool, &user.to_text()).await.unwrap();
    }
}

#[tokio::test]
async fn test_get_canister_to_principal_bulk_impl() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    let mut conn = redis_pool.get().await.unwrap();
    
    // Create test mappings
    let canister_principals = vec![
        (generate_test_principal(3000), generate_test_principal(30)),
        (generate_test_principal(3001), generate_test_principal(31)),
        (generate_test_principal(3002), generate_test_principal(32)),
    ];
    
    // Store test data in Redis
    for (canister_id, user_principal) in &canister_principals {
        let _: () = conn.hset(
            CANISTER_TO_PRINCIPAL_KEY,
            canister_id.to_text(),
            user_principal.to_text()
        ).await.unwrap();
    }
    
    // Execute - request all canisters
    let canisters = canister_principals.iter().map(|(c, _)| *c).collect();
    let req = CanisterToPrincipalReq { canisters };
    let result = get_canister_to_principal_bulk_impl(&redis_pool, req).await;
    
    // Verify
    assert!(result.is_ok());
    let res = result.unwrap();
    assert_eq!(res.mappings.len(), 3);
    
    // Check specific mappings
    for (canister_id, expected_principal) in &canister_principals {
        assert_eq!(res.mappings.get(canister_id), Some(expected_principal));
    }
    
    // Cleanup
    for (canister_id, _) in &canister_principals {
        let _: () = conn.hdel(CANISTER_TO_PRINCIPAL_KEY, canister_id.to_text()).await.unwrap();
    }
}

#[tokio::test]
async fn test_get_canister_to_principal_bulk_impl_partial_results() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    let mut conn = redis_pool.get().await.unwrap();
    
    // Store only some mappings
    let _: () = conn.hset(
        CANISTER_TO_PRINCIPAL_KEY,
        generate_test_principal(4000).to_text(),
        generate_test_principal(40).to_text()
    ).await.unwrap();
    
    let _: () = conn.hset(
        CANISTER_TO_PRINCIPAL_KEY,
        generate_test_principal(4002).to_text(),
        generate_test_principal(42).to_text()
    ).await.unwrap();
    
    // Execute - request includes non-existent canister
    let canisters = vec![
        generate_test_principal(4000),
        generate_test_principal(4001), // This one doesn't exist
        generate_test_principal(4002),
    ];
    let req = CanisterToPrincipalReq { canisters };
    let result = get_canister_to_principal_bulk_impl(&redis_pool, req).await;
    
    // Verify
    assert!(result.is_ok());
    let res = result.unwrap();
    assert_eq!(res.mappings.len(), 2); // Only 2 mappings should be returned
    
    assert_eq!(res.mappings.get(&generate_test_principal(4000)), Some(&generate_test_principal(40)));
    assert_eq!(res.mappings.get(&generate_test_principal(4001)), None);
    assert_eq!(res.mappings.get(&generate_test_principal(4002)), Some(&generate_test_principal(42)));
    
    // Cleanup
    let _: () = conn.hdel(CANISTER_TO_PRINCIPAL_KEY, generate_test_principal(4000).to_text()).await.unwrap();
    let _: () = conn.hdel(CANISTER_TO_PRINCIPAL_KEY, generate_test_principal(4002).to_text()).await.unwrap();
}

#[tokio::test]
async fn test_get_canister_to_principal_bulk_impl_empty_request() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    
    // Execute with empty request
    let req = CanisterToPrincipalReq { canisters: vec![] };
    let result = get_canister_to_principal_bulk_impl(&redis_pool, req).await;
    
    // Verify
    assert!(result.is_ok());
    let res = result.unwrap();
    assert!(res.mappings.is_empty());
}

#[tokio::test]
async fn test_get_canister_to_principal_bulk_impl_invalid_principal_in_redis() {
    // Setup
    let redis_pool = create_test_redis_pool().await.expect("Redis pool");
    let mut conn = redis_pool.get().await.unwrap();
    
    let canister_id = generate_test_principal(5000);
    
    // Store invalid principal string
    let _: () = conn.hset(
        CANISTER_TO_PRINCIPAL_KEY,
        canister_id.to_text(),
        "invalid-principal-format"
    ).await.unwrap();
    
    // Execute
    let req = CanisterToPrincipalReq { canisters: vec![canister_id] };
    let result = get_canister_to_principal_bulk_impl(&redis_pool, req).await;
    
    // Verify - should succeed but return empty mappings since the principal is invalid
    assert!(result.is_ok());
    let res = result.unwrap();
    assert!(res.mappings.is_empty());
    
    // Cleanup
    let _: () = conn.hdel(CANISTER_TO_PRINCIPAL_KEY, canister_id.to_text()).await.unwrap();
}