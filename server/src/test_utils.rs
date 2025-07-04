#[cfg(test)]
pub mod test_helpers {
    use candid::Principal;
    use types::{SetUserMetadataReqMetadata, UserMetadata};

    use crate::{
        state::{init_redis_with_url, RedisPool},
        utils::error::Result,
    };

    /// Create a test Redis pool
    pub async fn create_test_redis_pool() -> Result<RedisPool> {
        let redis_url = std::env::var("TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        init_redis_with_url(&redis_url).await
    }

    /// Generate a test principal
    pub fn generate_test_principal(id: u64) -> Principal {
        // Create principals from bytes to ensure they're valid
        let mut bytes = vec![0u8; 29];
        bytes[0] = (id & 0xFF) as u8;
        bytes[1] = ((id >> 8) & 0xFF) as u8;
        bytes[2] = ((id >> 16) & 0xFF) as u8;
        bytes[3] = ((id >> 24) & 0xFF) as u8;
        Principal::from_slice(&bytes)
    }

    /// Create test user metadata
    pub fn create_test_user_metadata(user_id: u64, canister_id: u64) -> UserMetadata {
        UserMetadata {
            user_canister_id: generate_test_principal(canister_id),
            user_name: format!("test_user_{}", user_id),
            notification_key: None,
            is_migrated: false,
        }
    }

    /// Create test metadata for SetUserMetadataReq
    pub fn create_test_metadata_req(
        canister_id: u64,
        user_name: &str,
    ) -> SetUserMetadataReqMetadata {
        SetUserMetadataReqMetadata {
            user_canister_id: generate_test_principal(canister_id),
            user_name: user_name.to_string(),
        }
    }

    /// Clean up test data with a specific prefix
    pub async fn cleanup_test_data(redis_pool: &RedisPool, key_prefix: &str) -> Result<()> {
        use redis::AsyncCommands;

        let mut conn = redis_pool.get().await?;
        let pattern = format!("{}*", key_prefix);
        let keys: Vec<String> = conn.keys(&pattern).await?;

        if !keys.is_empty() {
            let _: () = conn.del(keys).await?;
        }

        Ok(())
    }
}
