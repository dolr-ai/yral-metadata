// Unit tests are temporarily commented out due to signature changes
// (functions now expect &Arc<DragonflyPool> instead of &mut MockRedisConnection)
// TODO: Update mocks to work with DragonflyPool

#[cfg(test)]
mod integration_tests {
    use crate::firebase::Firebase;
    use crate::firebase::notifications::utils;

    #[tokio::test]
    async fn test_get_notification_key_nonexistent_returns_error() {
        let firebase = Firebase::new()
            .await
            .expect("Failed to create Firebase client");

        let result = firebase
            .get_notification_key("notification_key_nonexistent_user_12345")
            .await;

        assert!(
            result.is_err(),
            "Should fail for non-existent notification_key_name"
        );
        let err = result.unwrap_err();
        println!("Expected error for non-existent key: {:?}", err);
    }

    #[tokio::test]
    async fn test_create_then_get_notification_key() {
        let firebase = Firebase::new()
            .await
            .expect("Failed to create Firebase client");

        // Use a unique key name so tests don't collide
        let test_principal = format!("ci_test_user_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis());
        let notification_key_name = utils::get_notification_key_name_from_principal(&test_principal);

        // A dummy FCM registration token - use a known valid one from your project,
        // or a fake one (create will succeed with a fake token, FCM just stores it).
        // Using a plausible-looking fake token for the test.
        let fake_registration_token = format!("fake_token_for_ci_test_{}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis());

        // Step 1: Create a device group
        let create_body = serde_json::to_value(utils::get_create_request_body(
            notification_key_name.clone(),
            fake_registration_token.clone(),
        ))
        .expect("Failed to serialize create request");

        let create_result = firebase.update_notification_devices(create_body).await;
        assert!(
            create_result.is_ok(),
            "Failed to create device group: {:?}",
            create_result.err()
        );
        let created_key = create_result
            .unwrap()
            .expect("Create should return a notification_key");
        println!("Created device group with key: {}", created_key);

        // Step 2: Retrieve the notification key via GET
        let get_result = firebase
            .get_notification_key(&notification_key_name)
            .await;

        assert!(
            get_result.is_ok(),
            "get_notification_key failed: {:?}",
            get_result.err()
        );
        let retrieved_key = get_result.unwrap();
        println!("Retrieved notification_key: {}", retrieved_key);
        assert!(
            !retrieved_key.is_empty(),
            "Retrieved notification_key should not be empty"
        );

        // Step 3: Clean up - remove the token to effectively delete the group
        let remove_body = serde_json::to_value(utils::get_remove_request_body(
            notification_key_name.clone(),
            created_key.clone(),
            fake_registration_token,
        ))
        .expect("Failed to serialize remove request");

        let _ = firebase.update_notification_devices(remove_body).await;
        println!("Cleaned up test device group");
    }
}
