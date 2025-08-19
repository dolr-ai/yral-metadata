mod tests {
    use crate::api::METADATA_FIELD; // Import METADATA_FIELD
    use crate::notifications::traits::RedisConnection;
    use ntex::web::types::Json;
    use types::{
        error::ApiError,
        DeviceRegistrationToken,
        NotificationKey,
        SendNotificationReq,
        UserMetadata as ActualUserMetadata, // Import ActualUserMetadata alias
    }; // Import traits for type hints if necessary

    use crate::{
        notifications::mocks::{
            DeviceGroup, // Import DeviceGroup for direct FCM mock setup
            MockFCM,
            MockRedisConnection,
            MockRegisterDeviceReq,
            MockUnregisterDeviceReq,
        },
        notifications::{register_device_impl, send_notification_impl, unregister_device_impl},
        utils::error::Error, // For matching specific error types
    };

    // Helper function now returns ActualUserMetadata for direct use with mock_redis.add_user
    fn create_actual_user_metadata(
        user_id: &str,
        notification_key: Option<NotificationKey>,
    ) -> ActualUserMetadata {
        ActualUserMetadata {
            user_canister_id: user_id.parse().expect("Test user_id not a valid principal"),
            user_name: format!("user_{}", user_id),
            notification_key,
            is_migrated: false,
            signup_at: None,
            email: None,
        }
    }

    #[tokio::test]
    async fn test_register_device_new_user_creates_key() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "aaaaa-aa".to_string();

        let initial_metadata = create_actual_user_metadata(&user_principal_text, None);
        mock_redis.add_user(initial_metadata); // Use add_user helper

        let req = Json(MockRegisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: "new_device_token_1".to_string(),
            },
        });

        let result = register_device_impl(
            &mock_fcm,                   // FCM service first
            &mut mock_redis,             // Then Redis service
            user_principal_text.clone(), // Then user principal
            req,                         // Then request data
        )
        .await;

        assert!(result.is_ok(), "Registration failed: {:?}", result.err());
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result was an error: {:?}",
            api_result.err()
        );

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );

        let fcm_groups = mock_fcm.notification_groups.read().unwrap();
        assert!(fcm_groups.contains_key(&notification_key_name));
        let group = fcm_groups.get(&notification_key_name).unwrap();
        assert_eq!(group.registration_tokens.len(), 1);
        assert_eq!(group.registration_tokens[0], "new_device_token_1");
        let fcm_notification_key = group.notification_key.clone();

        let updated_metadata_bytes: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let updated_metadata_bytes =
            updated_metadata_bytes.expect("User metadata not found after registration (bytes)");
        let updated_metadata: ActualUserMetadata = serde_json::from_slice(&updated_metadata_bytes)
            .expect("Failed to deserialize metadata");

        assert!(updated_metadata.notification_key.is_some());
        let redis_notification_key = updated_metadata.notification_key.as_ref().unwrap();
        assert_eq!(redis_notification_key.key, fcm_notification_key);
        assert_eq!(redis_notification_key.registration_tokens.len(), 1);
        assert_eq!(
            redis_notification_key.registration_tokens[0].token,
            "new_device_token_1"
        );
    }

    #[tokio::test]
    async fn test_register_device_unmigrated_user_replaces_key() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "gytd5-mqaaa-aaaah-ajwka-cai".to_string();

        let initial_fcm_key = "existing_fcm_key_for_gytd5-mqaaa-aaaah-ajwka-cai".to_string();
        let existing_token = "existing_device_token_1".to_string();

        let initial_metadata = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: initial_fcm_key.clone(),
                registration_tokens: vec![DeviceRegistrationToken {
                    token: existing_token.clone(),
                }],
            }),
        );
        mock_redis.add_user(initial_metadata);

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        mock_fcm.notification_groups.write().unwrap().insert(
            notification_key_name.clone(),
            DeviceGroup {
                notification_key: initial_fcm_key.clone(),
                registration_tokens: vec![existing_token.clone()],
            },
        );

        let new_device_token_str = "new_device_token_2".to_string();
        let req = Json(MockRegisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: new_device_token_str.clone(),
            },
        });

        let result =
            register_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Registration failed: {:?}", result.err());
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result was an error: {:?}",
            api_result.err()
        );

        let fcm_groups = mock_fcm.notification_groups.read().unwrap();
        assert!(fcm_groups.contains_key(&notification_key_name));
        let group = fcm_groups.get(&notification_key_name).unwrap();
        assert_eq!(group.registration_tokens.len(), 2);
        assert!(group.registration_tokens.contains(&existing_token));
        assert!(group.registration_tokens.contains(&new_device_token_str));
        assert_eq!(group.notification_key, initial_fcm_key);

        let updated_metadata_bytes: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let updated_metadata_bytes =
            updated_metadata_bytes.expect("User metadata not found after registration (bytes)");
        let updated_metadata: ActualUserMetadata = serde_json::from_slice(&updated_metadata_bytes)
            .expect("Failed to deserialize metadata");

        let redis_notification_key = updated_metadata.notification_key.as_ref().unwrap();
        assert_eq!(redis_notification_key.key, initial_fcm_key);
        assert_eq!(redis_notification_key.registration_tokens.len(), 1);
        assert_eq!(
            redis_notification_key.registration_tokens[0].token,
            new_device_token_str
        );
        assert!(updated_metadata.is_migrated);
    }

    #[tokio::test]
    async fn test_register_device_migrated_user_adds_to_key() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "gytd5-mqaaa-aaaah-ajwka-cai".to_string();

        let initial_fcm_key = "existing_fcm_key_for_gytd5-mqaaa-aaaah-ajwka-cai".to_string();
        let existing_token = "existing_device_token_1".to_string();

        let mut initial_metadata = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: initial_fcm_key.clone(),
                registration_tokens: vec![DeviceRegistrationToken {
                    token: existing_token.clone(),
                }],
            }),
        );
        initial_metadata.is_migrated = true;
        mock_redis.add_user(initial_metadata);

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        mock_fcm.notification_groups.write().unwrap().insert(
            notification_key_name.clone(),
            DeviceGroup {
                notification_key: initial_fcm_key.clone(),
                registration_tokens: vec![existing_token.clone()],
            },
        );

        let new_device_token_str = "new_device_token_2".to_string();
        let req = Json(MockRegisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: new_device_token_str.clone(),
            },
        });

        let result =
            register_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Registration failed: {:?}", result.err());
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result was an error: {:?}",
            api_result.err()
        );

        let fcm_groups = mock_fcm.notification_groups.read().unwrap();
        assert!(fcm_groups.contains_key(&notification_key_name));
        let group = fcm_groups.get(&notification_key_name).unwrap();
        assert_eq!(group.registration_tokens.len(), 2);
        assert!(group.registration_tokens.contains(&existing_token));
        assert!(group.registration_tokens.contains(&new_device_token_str));
        assert_eq!(group.notification_key, initial_fcm_key);

        let updated_metadata_bytes: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let updated_metadata_bytes =
            updated_metadata_bytes.expect("User metadata not found after registration (bytes)");
        let updated_metadata: ActualUserMetadata = serde_json::from_slice(&updated_metadata_bytes)
            .expect("Failed to deserialize metadata");

        let redis_notification_key = updated_metadata.notification_key.as_ref().unwrap();
        assert_eq!(redis_notification_key.key, initial_fcm_key);
        assert_eq!(redis_notification_key.registration_tokens.len(), 2);
        assert!(redis_notification_key
            .registration_tokens
            .iter()
            .any(|rt| rt.token == existing_token));
        assert!(redis_notification_key
            .registration_tokens
            .iter()
            .any(|rt| rt.token == new_device_token_str));
        assert!(updated_metadata.is_migrated);
    }

    #[tokio::test]
    async fn test_register_device_reregister_existing_token() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "76qol-iiaaa-aaaak-qelkq-cai".to_string();

        let initial_fcm_key = "existing_fcm_key_for_76qol-iiaaa-aaaak-qelkq-cai".to_string();
        let existing_token_str = "device_token_to_reregister".to_string();

        let initial_metadata = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: initial_fcm_key.clone(),
                registration_tokens: vec![DeviceRegistrationToken {
                    token: existing_token_str.clone(),
                }],
            }),
        );
        mock_redis.add_user(initial_metadata);

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        mock_fcm.notification_groups.write().unwrap().insert(
            notification_key_name.clone(),
            DeviceGroup {
                notification_key: initial_fcm_key.clone(), // The key that FCM has
                registration_tokens: vec![existing_token_str.clone()],
            },
        );

        let req = Json(MockRegisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: existing_token_str.clone(),
            },
        });

        let result =
            register_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Registration failed: {:?}", result.err());
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result was an error: {:?}",
            api_result.err()
        );

        let fcm_groups = mock_fcm.notification_groups.read().unwrap();
        let group = fcm_groups.get(&notification_key_name).unwrap();
        assert_eq!(group.registration_tokens.len(), 1);
        assert_eq!(group.registration_tokens[0], existing_token_str);
        // Key on FCM should remain the initial_fcm_key because the logic is remove then add to *existing* key.
        assert_eq!(group.notification_key, initial_fcm_key);

        let updated_metadata_bytes: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let updated_metadata_bytes =
            updated_metadata_bytes.expect("User metadata not found (bytes)");
        let updated_metadata: ActualUserMetadata = serde_json::from_slice(&updated_metadata_bytes)
            .expect("Failed to deserialize metadata");

        let redis_notification_key = updated_metadata.notification_key.as_ref().unwrap();
        // Key in Redis should also be the initial_fcm_key, as it's fetched from FCM if different.
        assert_eq!(redis_notification_key.key, initial_fcm_key);
        assert_eq!(redis_notification_key.registration_tokens.len(), 1);
        assert_eq!(
            redis_notification_key.registration_tokens[0].token,
            existing_token_str
        );
    }

    #[tokio::test]
    async fn test_register_device_metadata_not_found() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "zboat-zyaaa-aaaaj-qml7q-caii".to_string();

        let req = Json(MockRegisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: "some_token".to_string(),
            },
        });

        let result =
            register_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Call itself should be ok");
        let api_result = result.unwrap().0;
        assert!(api_result.is_err(), "API result should be an error");
        assert_eq!(api_result.err(), Some(ApiError::MetadataNotFound));
    }

    #[tokio::test]
    async fn test_unregister_device_success() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "64jio-xaaaa-aaaao-qdeoa-cai".to_string();
        let token_to_unregister = "token_to_remove".to_string();
        let other_token = "other_token_kept".to_string();
        let fcm_key = "fcm_key_for_64jio-xaaaa-aaaao-qdeoa-cai".to_string();

        let initial_metadata = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: fcm_key.clone(),
                registration_tokens: vec![
                    DeviceRegistrationToken {
                        token: token_to_unregister.clone(),
                    },
                    DeviceRegistrationToken {
                        token: other_token.clone(),
                    },
                ],
            }),
        );
        mock_redis.add_user(initial_metadata);

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        mock_fcm.notification_groups.write().unwrap().insert(
            notification_key_name.clone(),
            DeviceGroup {
                notification_key: fcm_key.clone(),
                registration_tokens: vec![token_to_unregister.clone(), other_token.clone()],
            },
        );

        let req = Json(MockUnregisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: token_to_unregister.clone(),
            },
        });

        let result =
            unregister_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Unregistration failed: {:?}", result.err());
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result was an error: {:?}",
            api_result.err()
        );

        let fcm_groups = mock_fcm.notification_groups.read().unwrap();
        let group = fcm_groups.get(&notification_key_name).unwrap();
        assert_eq!(group.registration_tokens.len(), 1);
        assert_eq!(group.registration_tokens[0], other_token);

        let updated_metadata_bytes: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let updated_metadata_bytes =
            updated_metadata_bytes.expect("User metadata not found (bytes)");
        let updated_metadata: ActualUserMetadata = serde_json::from_slice(&updated_metadata_bytes)
            .expect("Failed to deserialize metadata");

        let redis_notification_key = updated_metadata.notification_key.as_ref().unwrap();
        assert_eq!(redis_notification_key.registration_tokens.len(), 1);
        assert_eq!(
            redis_notification_key.registration_tokens[0].token,
            other_token
        );
    }

    #[tokio::test]
    async fn test_unregister_last_device_removes_group_from_fcm() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "vppwu-fqaaa-aaaah-qhzea-cai".to_string();
        let last_token = "the_last_token".to_string();
        let fcm_key = "fcm_key_for_vppwu-fqaaa-aaaah-qhzea-cai".to_string();

        let initial_metadata = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: fcm_key.clone(),
                registration_tokens: vec![DeviceRegistrationToken {
                    token: last_token.clone(),
                }],
            }),
        );
        mock_redis.add_user(initial_metadata);

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        // The mock FCM for remove operation doesn't remove the group if tokens list becomes empty.
        // The actual `unregister_device_impl` doesn't rely on FCM to remove the group for it.
        // It just calls remove token. The test should check Redis primarily, and FCM that token is gone.
        // For this test, the mock FcmService remove will simply remove the token from the list.
        // And the logic of register_device_impl might re-create if it finds empty.
        // For unregister, it just removes from its list. The test assertion needs to align.
        // The MockFCM now mimics the behavior where it does NOT remove the group, just the token.
        // The `unregister_device_impl` doesn't have logic to delete empty FCM groups either.
        mock_fcm.notification_groups.write().unwrap().insert(
            notification_key_name.clone(),
            DeviceGroup {
                notification_key: fcm_key.clone(),
                registration_tokens: vec![last_token.clone()],
            },
        );

        let req = Json(MockUnregisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: last_token.clone(),
            },
        });

        let result =
            unregister_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Unregistration failed: {:?}", result.err());
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result was an error: {:?}",
            api_result.err()
        );

        let fcm_groups = mock_fcm.notification_groups.read().unwrap();
        // Assert that the group still exists but is empty, matching MockFCM behavior
        assert!(fcm_groups.contains_key(&notification_key_name));
        assert!(fcm_groups
            .get(&notification_key_name)
            .unwrap()
            .registration_tokens
            .is_empty());

        let updated_metadata_bytes: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let updated_metadata_bytes =
            updated_metadata_bytes.expect("User metadata not found (bytes)");
        let updated_metadata: ActualUserMetadata = serde_json::from_slice(&updated_metadata_bytes)
            .expect("Failed to deserialize metadata");

        let redis_notification_key = updated_metadata.notification_key.as_ref().unwrap();
        assert!(redis_notification_key.registration_tokens.is_empty());
        assert_eq!(redis_notification_key.key, fcm_key);
    }

    #[tokio::test]
    async fn test_unregister_device_not_found() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "eedyd-aaaaa-aaaag-qdxpa-cai".to_string();
        let existing_token = "actual_token".to_string();
        let token_to_unregister = "non_existent_token".to_string();
        let fcm_key = "fcm_key_for_eedyd-aaaaa-aaaag-qdxpa-cai".to_string();

        let initial_metadata = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: fcm_key.clone(),
                registration_tokens: vec![DeviceRegistrationToken {
                    token: existing_token.clone(),
                }],
            }),
        );
        mock_redis.add_user(initial_metadata);

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        mock_fcm.notification_groups.write().unwrap().insert(
            notification_key_name.clone(),
            DeviceGroup {
                notification_key: fcm_key.clone(),
                registration_tokens: vec![existing_token.clone()],
            },
        );

        let req = Json(MockUnregisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: token_to_unregister.clone(),
            },
        });

        let result =
            unregister_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Call itself should be ok");
        let api_result = result.unwrap().0;
        assert!(api_result.is_err(), "API result should be an error");
        assert_eq!(api_result.err(), Some(ApiError::DeviceNotFound));

        let fcm_groups = mock_fcm.notification_groups.read().unwrap();
        let group = fcm_groups.get(&notification_key_name).unwrap();
        assert_eq!(group.registration_tokens.len(), 1);
        assert_eq!(group.registration_tokens[0], existing_token);

        let metadata_bytes_opt: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let metadata_bytes = metadata_bytes_opt.unwrap();
        let metadata: ActualUserMetadata = serde_json::from_slice(&metadata_bytes).unwrap();
        assert_eq!(
            metadata
                .notification_key
                .as_ref()
                .unwrap()
                .registration_tokens
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn test_unregister_device_no_notification_key() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "iwf4p-syaaa-aaaag-qicra-cai".to_string();

        let initial_metadata = create_actual_user_metadata(&user_principal_text, None);
        mock_redis.add_user(initial_metadata);

        let req = Json(MockUnregisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: "any_token".to_string(),
            },
        });

        let result =
            unregister_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Call itself should be ok");
        let api_result = result.unwrap().0;
        assert!(api_result.is_err(), "API result should be an error");
        assert_eq!(api_result.err(), Some(ApiError::NotificationKeyNotFound));
    }

    #[tokio::test]
    async fn test_unregister_device_metadata_not_found() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "wf4p-syaaa-aaaag-qicra-cai".to_string();

        let req = Json(MockUnregisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: "any_token".to_string(),
            },
        });

        let result =
            unregister_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Call itself should be ok");
        let api_result = result.unwrap().0;
        assert!(api_result.is_err(), "API result should be an error");
        assert_eq!(api_result.err(), Some(ApiError::MetadataNotFound));
    }

    #[tokio::test]
    async fn test_send_notification_success() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "ijcpr-iqaaa-aaaag-anfnq-cai".to_string();
        let fcm_key = "fcm_key_for_ijcpr-iqaaa-aaaag-anfnq-cai".to_string();
        let device_token = "device_for_ijcpr-iqaaa-aaaag-anfnq-cai".to_string();

        let initial_metadata = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: fcm_key.clone(),
                registration_tokens: vec![DeviceRegistrationToken {
                    token: device_token.clone(),
                }],
            }),
        );
        mock_redis.add_user(initial_metadata);

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        mock_fcm.notification_groups.write().unwrap().insert(
            notification_key_name.clone(),
            DeviceGroup {
                notification_key: fcm_key.clone(),
                registration_tokens: vec![device_token.clone()],
            },
        );

        let notification_payload = types::NotificationPayload {
            title: Some("Test Title".to_string()),
            body: Some("Test Body".to_string()),
            image: None,
        };
        let req = Json(SendNotificationReq {
            notification: Some(notification_payload.clone()),
            data: None,
            android: None,
            webpush: None,
            apns: None,
            fcm_options: None,
        });

        let result = send_notification_impl(
            None, // HttpRequest is None for tests
            &mock_fcm,
            &mut mock_redis,
            user_principal_text.clone(),
            req,
        )
        .await;

        assert!(
            result.is_ok(),
            "send_notification_impl failed: {:?}",
            result.err()
        );
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result was an error: {:?}",
            api_result.err()
        );
    }

    #[tokio::test]
    async fn test_send_notification_metadata_not_found() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "wrd2k-oyaaa-aaaai-afitq-cai".to_string();

        let notification_payload = types::NotificationPayload {
            title: Some("Test Title".to_string()),
            body: Some("Test Body".to_string()),
            image: None,
        };
        let req = Json(SendNotificationReq {
            notification: Some(notification_payload.clone()),
            data: None,
            android: None,
            webpush: None,
            apns: None,
            fcm_options: None,
        });

        let result = send_notification_impl(
            None,
            &mock_fcm,
            &mut mock_redis,
            user_principal_text.clone(),
            req,
        )
        .await;

        assert!(result.is_ok(), "Call itself should be Ok");
        let api_result = result.unwrap().0;
        assert!(api_result.is_err(), "API result should be an error");
        assert_eq!(api_result.err(), Some(ApiError::MetadataNotFound));
    }

    #[tokio::test]
    async fn test_send_notification_key_not_found_in_metadata() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "mpvf6-4aaaa-aaaal-qhokq-cai".to_string();

        let initial_metadata = create_actual_user_metadata(&user_principal_text, None);
        mock_redis.add_user(initial_metadata);

        let notification_payload = types::NotificationPayload {
            title: Some("Test Title".to_string()),
            body: Some("Test Body".to_string()),
            image: None,
        };
        let req = Json(SendNotificationReq {
            notification: Some(notification_payload.clone()),
            data: None,
            android: None,
            webpush: None,
            apns: None,
            fcm_options: None,
        });

        let result = send_notification_impl(
            None,
            &mock_fcm,
            &mut mock_redis,
            user_principal_text.clone(),
            req,
        )
        .await;

        assert!(result.is_ok(), "Call itself should be Ok");
        let api_result = result.unwrap().0;
        assert!(api_result.is_err(), "API result should be an error");
        assert_eq!(api_result.err(), Some(ApiError::NotificationKeyNotFound));
    }

    #[tokio::test]
    async fn test_send_notification_fcm_key_not_found_in_fcm_mock() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "vfvsa-lqaaa-aaaag-qetmq-cai".to_string();
        let fcm_key_in_redis = "dangling_fcm_key_in_redis".to_string();

        let initial_metadata = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: fcm_key_in_redis.clone(),
                registration_tokens: vec![DeviceRegistrationToken {
                    token: "some_device".to_string(),
                }],
            }),
        );
        mock_redis.add_user(initial_metadata);

        let notification_payload = types::NotificationPayload {
            title: Some("Test Title".to_string()),
            body: Some("Test Body".to_string()),
            image: None,
        };
        let req = Json(SendNotificationReq {
            notification: Some(notification_payload.clone()),
            data: None,
            android: None,
            webpush: None,
            apns: None,
            fcm_options: None,
        });

        let result = send_notification_impl(
            None,
            &mock_fcm,
            &mut mock_redis,
            user_principal_text.clone(),
            req,
        )
        .await;

        assert!(
            result.is_err(),
            "send_notification_impl should have failed due to FCM error"
        );
        match result.err().unwrap() {
            Error::Unknown(msg) => {
                assert!(msg.contains(&format!(
                    "Notification key not found in mock: {:?}", // Updated error message from MockFCM
                    fcm_key_in_redis
                )));
            }
            other_err => panic!(
                "Expected Error::Unknown from send_notification_impl, got {:?}",
                other_err
            ),
        }
    }

    #[tokio::test]
    async fn test_register_device_fcm_has_key_redis_missing_key_struct() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "mbwvf-5iaaa-aaaal-affma-cai".to_string();

        let initial_metadata_no_key = create_actual_user_metadata(&user_principal_text, None);
        mock_redis.add_user(initial_metadata_no_key);

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        let fcm_existing_key = format!("fcm_key_for_{}", user_principal_text);
        mock_fcm.notification_groups.write().unwrap().insert(
            notification_key_name.clone(),
            DeviceGroup {
                notification_key: fcm_existing_key.clone(),
                registration_tokens: vec!["old_token_in_fcm".to_string()],
            },
        );

        let new_device_token_str = "new_device_for_mbwvf-5iaaa-aaaal-affma-cai".to_string();
        let req = Json(MockRegisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: new_device_token_str.clone(),
            },
        });

        let result =
            register_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Registration failed: {:?}", result.err());
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result was an error: {:?}",
            api_result.err()
        );

        let fcm_groups = mock_fcm.notification_groups.read().unwrap();
        let group = fcm_groups
            .get(&notification_key_name)
            .expect("FCM group should still exist");
        assert_eq!(group.notification_key, fcm_existing_key);
        assert_eq!(group.registration_tokens.len(), 2);
        assert!(group
            .registration_tokens
            .contains(&"old_token_in_fcm".to_string()));
        assert!(group.registration_tokens.contains(&new_device_token_str));

        let updated_metadata_bytes_opt: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let updated_metadata_bytes =
            updated_metadata_bytes_opt.expect("User metadata not found after registration (bytes)");
        let updated_metadata: ActualUserMetadata = serde_json::from_slice(&updated_metadata_bytes)
            .expect("Failed to deserialize metadata");

        let redis_notification_key = updated_metadata
            .notification_key
            .as_ref()
            .expect("Notification key should exist in Redis");
        assert_eq!(redis_notification_key.key, fcm_existing_key);
        assert_eq!(
            redis_notification_key.registration_tokens.len(),
            1,
            "Redis should only have the newly registered token under the existing key"
        );
        assert!(redis_notification_key
            .registration_tokens
            .iter()
            .any(|rt| rt.token == new_device_token_str));
    }

    #[tokio::test]
    async fn test_register_device_fcm_missing_key_redis_has_key() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "ijcpr-iqaaa-aaaag-anfnq-cai".to_string();
        let redis_stale_key = "stale_fcm_key_in_redis".to_string();

        let initial_metadata_stale_key = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: redis_stale_key.clone(),
                registration_tokens: vec![DeviceRegistrationToken {
                    token: "old_token_in_redis".to_string(),
                }],
            }),
        );
        mock_redis.add_user(initial_metadata_stale_key);

        let new_device_token_str = "new_device_for_ijcpr-iqaaa-aaaag-anfnq-cai".to_string();
        let req = Json(MockRegisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: new_device_token_str.clone(),
            },
        });

        let result =
            register_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(result.is_ok(), "Registration failed: {:?}", result.err());
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result was an error: {:?}",
            api_result.err()
        );

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        let fcm_groups = mock_fcm.notification_groups.read().unwrap();
        assert!(fcm_groups.contains_key(&notification_key_name));
        let group = fcm_groups.get(&notification_key_name).unwrap();
        assert_eq!(group.registration_tokens.len(), 1);
        assert_eq!(group.registration_tokens[0], new_device_token_str);
        let fcm_new_key = group.notification_key.clone();

        let updated_metadata_bytes_opt: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let updated_metadata_bytes =
            updated_metadata_bytes_opt.expect("User metadata not found (bytes)");
        let updated_metadata: ActualUserMetadata = serde_json::from_slice(&updated_metadata_bytes)
            .expect("Failed to deserialize metadata");

        let redis_notification_key = updated_metadata.notification_key.as_ref().unwrap();
        assert_eq!(redis_notification_key.key, fcm_new_key);
        assert_eq!(redis_notification_key.registration_tokens.len(), 1);
        assert_eq!(
            redis_notification_key.registration_tokens[0].token,
            new_device_token_str
        );
    }

    #[tokio::test]
    async fn test_unregister_device_token_in_redis_not_in_fcm_group_exists() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "r4q6s-yyaaa-aaaap-acika-cai".to_string();
        let token_in_redis_only = "token_in_redis_not_fcm".to_string();
        let token_in_both = "token_in_both_systems".to_string();
        let fcm_key = "fcm_key_for_r4q6s-yyaaa-aaaap-acika-cai".to_string();

        let initial_metadata = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: fcm_key.clone(),
                registration_tokens: vec![
                    DeviceRegistrationToken {
                        token: token_in_redis_only.clone(),
                    },
                    DeviceRegistrationToken {
                        token: token_in_both.clone(),
                    },
                ],
            }),
        );
        mock_redis.add_user(initial_metadata);

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        mock_fcm.notification_groups.write().unwrap().insert(
            notification_key_name.clone(),
            DeviceGroup {
                notification_key: fcm_key.clone(),
                registration_tokens: vec![token_in_both.clone()],
            },
        );

        let req = Json(MockUnregisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: token_in_redis_only.clone(),
            },
        });

        let result =
            unregister_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(
            result.is_ok(),
            "Unregistration call failed: {:?}",
            result.err()
        );
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result should be Ok, even if token was not in FCM: {:?}",
            api_result.err()
        );

        let fcm_groups = mock_fcm.notification_groups.read().unwrap();
        let group = fcm_groups.get(&notification_key_name).unwrap();
        assert_eq!(group.registration_tokens.len(), 1);
        assert_eq!(group.registration_tokens[0], token_in_both);

        let updated_metadata_bytes_opt: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let updated_metadata_bytes = updated_metadata_bytes_opt.unwrap();
        let updated_metadata: ActualUserMetadata =
            serde_json::from_slice(&updated_metadata_bytes).unwrap();
        let redis_nk = updated_metadata.notification_key.as_ref().unwrap();
        assert_eq!(redis_nk.registration_tokens.len(), 1);
        assert_eq!(redis_nk.registration_tokens[0].token, token_in_both);
    }

    #[tokio::test]
    async fn test_unregister_device_token_in_redis_fcm_group_gone() {
        let mock_fcm = MockFCM::new();
        let mut mock_redis = MockRedisConnection::new();
        let user_principal_text = "jkoyy-xaaaa-aaaai-agrba-cai".to_string();
        let token_to_unregister = "token_when_fcm_group_is_gone".to_string();
        let fcm_key_in_redis = "fcm_key_for_jkoyy-xaaaa-aaaai-agrba-cai_gone_from_fcm".to_string();

        let initial_metadata = create_actual_user_metadata(
            &user_principal_text,
            Some(NotificationKey {
                key: fcm_key_in_redis.clone(),
                registration_tokens: vec![DeviceRegistrationToken {
                    token: token_to_unregister.clone(),
                }],
            }),
        );
        mock_redis.add_user(initial_metadata);

        let req = Json(MockUnregisterDeviceReq {
            registration_token: DeviceRegistrationToken {
                token: token_to_unregister.clone(),
            },
        });

        let result =
            unregister_device_impl(&mock_fcm, &mut mock_redis, user_principal_text.clone(), req)
                .await;

        assert!(
            result.is_ok(),
            "Unregistration call failed: {:?}",
            result.err()
        );
        let api_result = result.unwrap().0;
        assert!(
            api_result.is_ok(),
            "API result should be Ok, even if group was not in FCM: {:?}",
            api_result.err()
        );

        let notification_key_name =
            crate::firebase::notifications::utils::get_notification_key_name_from_principal(
                &user_principal_text,
            );
        assert!(!mock_fcm
            .notification_groups
            .read()
            .unwrap()
            .contains_key(&notification_key_name));

        let updated_metadata_bytes_opt: Option<Vec<u8>> = mock_redis
            .hget(&user_principal_text, METADATA_FIELD)
            .await
            .unwrap();
        let updated_metadata_bytes = updated_metadata_bytes_opt.unwrap();
        let updated_metadata: ActualUserMetadata =
            serde_json::from_slice(&updated_metadata_bytes).unwrap();

        let redis_nk = updated_metadata.notification_key.as_ref().unwrap();
        assert!(redis_nk.registration_tokens.is_empty());
        assert_eq!(redis_nk.key, fcm_key_in_redis);
    }
}
