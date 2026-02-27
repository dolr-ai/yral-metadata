use super::implementation::*;
use crate::{
    api::store::MockMetadataKvStore,
    dragonfly::{format_to_dragonfly_key, TEST_KEY_PREFIX},
    test_utils::test_helpers::*,
};
use candid::Principal;
use types::{BulkGetUserMetadataReq, BulkUsers, CanisterToPrincipalReq, UserMetadata};

// ── helpers ───────────────────────────────────────────────────────────────────

/// Insert pre-serialised UserMetadata into the mock store at the user's hash key.
async fn seed_user(mock: &MockMetadataKvStore, user: Principal, metadata: &UserMetadata) {
    let key = format_to_dragonfly_key(TEST_KEY_PREFIX, &user.to_text());
    let bytes = serde_json::to_vec(metadata).unwrap();
    mock.insert(&key, METADATA_FIELD, bytes).await;
}

// ── set_user_metadata_core ────────────────────────────────────────────────────

#[tokio::test]
async fn test_set_user_metadata_valid_request() {
    let mock = MockMetadataKvStore::new();
    let user_principal = generate_unique_test_principal();
    let unique_key = generate_unique_test_key_prefix();
    let metadata = create_test_metadata_req(100, "testuser");

    let result =
        set_user_metadata_core(&mock, user_principal, &metadata, &unique_key, TEST_KEY_PREFIX)
            .await;
    assert!(result.is_ok(), "Failed: {:?}", result);

    // User metadata was stored.
    let user_key = format_to_dragonfly_key(TEST_KEY_PREFIX, &user_principal.to_text());
    assert!(mock.get_raw(&user_key, METADATA_FIELD).await.is_some());

    // Reverse index (canister → principal) was stored.
    let can2prin_key = format_to_dragonfly_key(TEST_KEY_PREFIX, &unique_key);
    let raw = mock
        .get_raw(&can2prin_key, &metadata.user_canister_id.to_text())
        .await;
    let stored_principal = raw.map(|b| String::from_utf8(b).unwrap());
    assert_eq!(stored_principal, Some(user_principal.to_text()));
}

#[tokio::test]
async fn test_set_user_metadata_updates_existing() {
    let mock = MockMetadataKvStore::new();
    let user_principal = generate_unique_test_principal();
    let unique_key = generate_unique_test_key_prefix();

    // First request: set username "originalname".
    let metadata1 = create_test_metadata_req(200, "originalname");
    set_user_metadata_core(&mock, user_principal, &metadata1, &unique_key, TEST_KEY_PREFIX)
        .await
        .unwrap();

    // Second request: change username to "updatedname".
    let metadata2 = create_test_metadata_req(200, "updatedname");
    let result =
        set_user_metadata_core(&mock, user_principal, &metadata2, &unique_key, TEST_KEY_PREFIX)
            .await;
    assert!(result.is_ok(), "Failed: {:?}", result);

    let user_key = format_to_dragonfly_key(TEST_KEY_PREFIX, &user_principal.to_text());
    let raw = mock.get_raw(&user_key, METADATA_FIELD).await.unwrap();
    let meta: UserMetadata = serde_json::from_slice(&raw).unwrap();
    assert_eq!(meta.user_name, "updatedname");

    // Old username-info key must be gone.
    let old_username_key =
        format_to_dragonfly_key(TEST_KEY_PREFIX, &username_info_key("originalname"));
    assert!(
        mock.get_raw(&old_username_key, METADATA_FIELD).await.is_none(),
        "old username-info key must be released"
    );

    // Third request: update only canister_id (empty username).
    let metadata3 = create_test_metadata_req(300, "");
    let result =
        set_user_metadata_core(&mock, user_principal, &metadata3, &unique_key, TEST_KEY_PREFIX)
            .await;
    assert!(result.is_ok(), "Failed: {:?}", result);

    let raw = mock.get_raw(&user_key, METADATA_FIELD).await.unwrap();
    let meta: UserMetadata = serde_json::from_slice(&raw).unwrap();
    assert_eq!(meta.user_name, "updatedname"); // name unchanged
    assert_eq!(meta.user_canister_id, metadata3.user_canister_id); // canister updated
}

// ── get_user_metadata_impl ────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_user_metadata_existing() {
    let mock = MockMetadataKvStore::new();
    let user_principal = generate_unique_test_principal();
    let test_metadata = create_test_user_metadata(3, 300);
    seed_user(&mock, user_principal, &test_metadata).await;

    let result =
        get_user_metadata_impl(&mock, user_principal.to_text(), TEST_KEY_PREFIX).await;

    assert!(result.is_ok(), "Failed: {:?}", result);
    let metadata = result.unwrap().unwrap();
    assert_eq!(metadata.user_name, "testuser3");
    assert_eq!(metadata.user_canister_id, test_metadata.user_canister_id);
}

#[tokio::test]
async fn test_get_user_metadata_not_found() {
    let mock = MockMetadataKvStore::new();
    let user_principal = generate_unique_test_principal();

    let result =
        get_user_metadata_impl(&mock, user_principal.to_text(), TEST_KEY_PREFIX).await;
    assert!(result.is_ok(), "Failed: {:?}", result);
    assert!(result.unwrap().is_none());
}

// ── delete_metadata_bulk_impl ─────────────────────────────────────────────────

#[tokio::test]
async fn test_delete_metadata_bulk() {
    let mock = MockMetadataKvStore::new();
    let unique_key = generate_unique_test_key_prefix();
    let users: Vec<Principal> = (0..3).map(|_| generate_unique_test_principal()).collect();

    for (i, user) in users.iter().enumerate() {
        let meta = create_test_user_metadata(5 + i as u64, 500 + i as u64);
        // Write user metadata.
        seed_user(&mock, *user, &meta).await;
        // Write reverse index entry.
        let can2prin_key = format_to_dragonfly_key(TEST_KEY_PREFIX, &unique_key);
        mock.insert(
            &can2prin_key,
            &meta.user_canister_id.to_text(),
            user.to_text().into_bytes(),
        )
        .await;
    }

    let bulk_users = BulkUsers { users: users.clone() };
    let result =
        delete_metadata_bulk_impl(&mock, &bulk_users, &unique_key, TEST_KEY_PREFIX).await;
    assert!(result.is_ok(), "Failed: {:?}", result);

    for user in &users {
        let key = format_to_dragonfly_key(TEST_KEY_PREFIX, &user.to_text());
        assert!(
            mock.get_raw(&key, METADATA_FIELD).await.is_none(),
            "user data should be deleted"
        );
    }
}

#[tokio::test]
async fn test_delete_metadata_bulk_empty_list() {
    let mock = MockMetadataKvStore::new();
    let unique_key = generate_unique_test_key_prefix();
    let bulk_users = BulkUsers { users: vec![] };

    let result =
        delete_metadata_bulk_impl(&mock, &bulk_users, &unique_key, TEST_KEY_PREFIX).await;
    assert!(result.is_ok(), "Failed: {:?}", result);
}

#[tokio::test]
async fn test_delete_metadata_bulk_large_batch() {
    let mock = MockMetadataKvStore::new();
    let unique_key = generate_unique_test_key_prefix();
    let users: Vec<Principal> = (0..300).map(|_| generate_unique_test_principal()).collect();

    for (i, user) in users.iter().enumerate() {
        let meta = create_test_user_metadata(i as u64, i as u64);
        seed_user(&mock, *user, &meta).await;
    }

    let bulk_users = BulkUsers { users: users.clone() };
    let result =
        delete_metadata_bulk_impl(&mock, &bulk_users, &unique_key, TEST_KEY_PREFIX)
            .await
            .expect("delete_metadata_bulk_impl should not fail");
    let _ = result;

    // Spot-check a few deletions.
    for user in users.iter().step_by(100) {
        let key = format_to_dragonfly_key(TEST_KEY_PREFIX, &user.to_text());
        assert!(mock.get_raw(&key, METADATA_FIELD).await.is_none());
    }
}

#[tokio::test]
async fn test_delete_metadata_bulk_releases_username() {
    let mock = MockMetadataKvStore::new();
    let user_principal = generate_unique_test_principal();
    let can2prin_key = generate_unique_test_key_prefix();

    // Build a valid alphanumeric username.
    let unique_key = generate_unique_test_key_prefix();
    let username: String = unique_key.chars().filter(|c| c.is_alphanumeric()).take(15).collect();

    // Register user with username.
    let metadata = create_test_metadata_req(42, &username);
    set_user_metadata_core(&mock, user_principal, &metadata, &can2prin_key, TEST_KEY_PREFIX)
        .await
        .expect("Failed to create user");

    // Confirm username-info key exists.
    let username_key =
        format_to_dragonfly_key(TEST_KEY_PREFIX, &username_info_key(&username));
    assert!(
        mock.get_raw(&username_key, METADATA_FIELD).await.is_some(),
        "username-info key must exist after user creation"
    );

    // Delete the user.
    let bulk_users = BulkUsers { users: vec![user_principal] };
    delete_metadata_bulk_impl(&mock, &bulk_users, &can2prin_key, TEST_KEY_PREFIX)
        .await
        .expect("Failed to delete user");

    // Username-info key must be gone.
    assert!(
        mock.get_raw(&username_key, METADATA_FIELD).await.is_none(),
        "username-info key must be released after user deletion"
    );

    // A new user must be able to claim the same username.
    let new_principal = generate_unique_test_principal();
    let new_metadata = create_test_metadata_req(43, &username);
    set_user_metadata_core(&mock, new_principal, &new_metadata, &can2prin_key, TEST_KEY_PREFIX)
        .await
        .expect("New user must be able to claim the released username");
}

// ── get_user_metadata_bulk_impl ───────────────────────────────────────────────

#[tokio::test]
async fn test_get_user_metadata_bulk_multiple_users() {
    let mock = MockMetadataKvStore::new();
    let users: Vec<Principal> = (0..3).map(|_| generate_unique_test_principal()).collect();

    // Seed only users[0] and users[2]; users[1] is absent.
    let meta0 = create_test_user_metadata(20, 2000);
    seed_user(&mock, users[0], &meta0).await;
    let meta2 = create_test_user_metadata(22, 2002);
    seed_user(&mock, users[2], &meta2).await;

    let req = BulkGetUserMetadataReq { users: users.clone() };
    let result = get_user_metadata_bulk_impl(&mock, req, TEST_KEY_PREFIX).await;

    assert!(result.is_ok(), "Failed: {:?}", result);
    let results = result.unwrap();
    assert_eq!(results.len(), 3);
    assert!(results[&users[0]].is_some());
    assert!(results[&users[1]].is_none());
    assert!(results[&users[2]].is_some());
}

#[tokio::test]
async fn test_get_user_metadata_bulk_empty_request() {
    let mock = MockMetadataKvStore::new();
    let req = BulkGetUserMetadataReq { users: vec![] };
    let result = get_user_metadata_bulk_impl(&mock, req, TEST_KEY_PREFIX).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_get_user_metadata_bulk_concurrent_processing() {
    let mock = MockMetadataKvStore::new();
    let users: Vec<Principal> = (0..20).map(|_| generate_unique_test_principal()).collect();

    for (i, user) in users.iter().enumerate() {
        seed_user(&mock, *user, &create_test_user_metadata(i as u64, i as u64)).await;
    }

    let req = BulkGetUserMetadataReq { users: users.clone() };
    let result = get_user_metadata_bulk_impl(&mock, req, TEST_KEY_PREFIX).await;

    assert!(result.is_ok(), "Failed: {:?}", result);
    let results = result.unwrap();
    assert_eq!(results.len(), 20);
    for user in &users {
        assert!(results[user].is_some());
    }
}

// ── get_canister_to_principal_bulk_impl ───────────────────────────────────────

#[tokio::test]
async fn test_get_canister_to_principal_bulk_impl() {
    let mock = MockMetadataKvStore::new();
    let unique_key = generate_unique_test_key_prefix();

    let pairs: Vec<(Principal, Principal)> = (0..3)
        .map(|_| (generate_unique_test_principal(), generate_unique_test_principal()))
        .collect();

    let can2prin_key = format_to_dragonfly_key(TEST_KEY_PREFIX, &unique_key);
    for (canister, user) in &pairs {
        mock.insert(&can2prin_key, &canister.to_text(), user.to_text().into_bytes())
            .await;
    }

    let canisters = pairs.iter().map(|(c, _)| *c).collect();
    let req = CanisterToPrincipalReq { canisters };
    let result =
        get_canister_to_principal_bulk_impl(&mock, req, &unique_key, TEST_KEY_PREFIX).await;

    assert!(result.is_ok(), "Failed: {:?}", result);
    let res = result.unwrap();
    assert_eq!(res.mappings.len(), 3);
    for (canister, user) in &pairs {
        assert_eq!(res.mappings.get(canister), Some(user));
    }
}

#[tokio::test]
async fn test_get_canister_to_principal_bulk_impl_partial_results() {
    let mock = MockMetadataKvStore::new();
    let unique_key = generate_unique_test_key_prefix();

    let canister1 = generate_unique_test_principal();
    let canister2 = generate_unique_test_principal();
    let canister3 = generate_unique_test_principal(); // not seeded
    let user1 = generate_unique_test_principal();
    let user2 = generate_unique_test_principal();

    let can2prin_key = format_to_dragonfly_key(TEST_KEY_PREFIX, &unique_key);
    mock.insert(&can2prin_key, &canister1.to_text(), user1.to_text().into_bytes())
        .await;
    mock.insert(&can2prin_key, &canister2.to_text(), user2.to_text().into_bytes())
        .await;

    let req = CanisterToPrincipalReq {
        canisters: vec![canister1, canister3, canister2],
    };
    let result =
        get_canister_to_principal_bulk_impl(&mock, req, &unique_key, TEST_KEY_PREFIX).await;

    assert!(result.is_ok(), "Failed: {:?}", result);
    let res = result.unwrap();
    assert_eq!(res.mappings.len(), 2);
    assert_eq!(res.mappings.get(&canister1), Some(&user1));
    assert_eq!(res.mappings.get(&canister3), None);
    assert_eq!(res.mappings.get(&canister2), Some(&user2));
}

#[tokio::test]
async fn test_get_canister_to_principal_bulk_impl_empty_request() {
    let mock = MockMetadataKvStore::new();
    let unique_key = generate_unique_test_key_prefix();
    let req = CanisterToPrincipalReq { canisters: vec![] };
    let result =
        get_canister_to_principal_bulk_impl(&mock, req, &unique_key, TEST_KEY_PREFIX).await;
    assert!(result.is_ok(), "Failed: {:?}", result);
    assert!(result.unwrap().mappings.is_empty());
}

#[tokio::test]
async fn test_get_canister_to_principal_bulk_impl_invalid_principal_in_redis() {
    let mock = MockMetadataKvStore::new();
    let unique_key = generate_unique_test_key_prefix();
    let canister_id = generate_unique_test_principal();

    let can2prin_key = format_to_dragonfly_key(TEST_KEY_PREFIX, &unique_key);
    mock.insert(
        &can2prin_key,
        &canister_id.to_text(),
        b"invalid-principal-format".to_vec(),
    )
    .await;

    let req = CanisterToPrincipalReq { canisters: vec![canister_id] };
    let result =
        get_canister_to_principal_bulk_impl(&mock, req, &unique_key, TEST_KEY_PREFIX).await;

    assert!(result.is_ok(), "Failed: {:?}", result);
    assert!(result.unwrap().mappings.is_empty()); // invalid principal skipped
}

#[tokio::test]
async fn test_get_canister_to_principal_bulk_impl_large_batch() {
    let mock = MockMetadataKvStore::new();
    let unique_key = generate_unique_test_key_prefix();

    let pairs: Vec<(Principal, Principal)> = (0..500)
        .map(|_| (generate_unique_test_principal(), generate_unique_test_principal()))
        .collect();

    let can2prin_key = format_to_dragonfly_key(TEST_KEY_PREFIX, &unique_key);
    for (canister, user) in &pairs {
        mock.insert(&can2prin_key, &canister.to_text(), user.to_text().into_bytes())
            .await;
    }

    let canisters = pairs.iter().map(|(c, _)| *c).collect();
    let req = CanisterToPrincipalReq { canisters };
    let result =
        get_canister_to_principal_bulk_impl(&mock, req, &unique_key, TEST_KEY_PREFIX).await;

    assert!(result.is_ok(), "Failed: {:?}", result);
    let res = result.unwrap();
    assert_eq!(res.mappings.len(), 500);

    for &idx in &[0usize, 100, 200, 300, 499] {
        let (canister, user) = &pairs[idx];
        assert_eq!(res.mappings.get(canister), Some(user));
    }
}
