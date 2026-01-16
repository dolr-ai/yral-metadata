#[cfg(test)]
pub mod test_helpers {
    use candid::Principal;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::{fs, thread};
    use types::{SetUserMetadataReqMetadata, UserMetadata};

    use crate::dragonfly::{DragonflyPool, TEST_KEY_PREFIX};
    use crate::{
        state::{init_redis_with_url, RedisPool},
        utils::error::Result,
    };

    /// Global counter for generating unique test principals
    static PRINCIPAL_COUNTER: AtomicU64 = AtomicU64::new(0);

    // Thread-local storage for used principals per test thread (currently unused but kept for future use)
    thread_local! {
        static USED_PRINCIPALS: Mutex<HashSet<u64>> = Mutex::new(HashSet::new());
    }

    /// Create a test Redis pool
    pub async fn create_test_redis_pool() -> Result<RedisPool> {
        let redis_url = std::env::var("TEST_REDIS_URL").unwrap();

        init_redis_with_url(&redis_url).await
    }

    /// Generate a unique test principal that won't collide across threads
    pub fn generate_unique_test_principal() -> Principal {
        // Use a combination of timestamp, thread ID, and atomic counter for uniqueness
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let thread_id = thread::current().id();
        let thread_hash = format!("{:?}", thread_id)
            .chars()
            .map(|c| c as u64)
            .fold(0u64, |acc, x| acc.wrapping_add(x));

        let counter = PRINCIPAL_COUNTER.fetch_add(1, Ordering::SeqCst);

        // Combine all sources of uniqueness
        let unique_id = timestamp.wrapping_add(thread_hash).wrapping_add(counter);

        // Create principals from bytes to ensure they're valid
        let mut bytes = vec![0u8; 29];
        bytes[0] = (unique_id & 0xFF) as u8;
        bytes[1] = ((unique_id >> 8) & 0xFF) as u8;
        bytes[2] = ((unique_id >> 16) & 0xFF) as u8;
        bytes[3] = ((unique_id >> 24) & 0xFF) as u8;
        bytes[4] = ((unique_id >> 32) & 0xFF) as u8;
        bytes[5] = ((unique_id >> 40) & 0xFF) as u8;
        bytes[6] = ((unique_id >> 48) & 0xFF) as u8;
        bytes[7] = ((unique_id >> 56) & 0xFF) as u8;

        Principal::from_slice(&bytes)
    }

    /// Generate a test principal (backward compatibility)
    /// This now generates unique principals per thread + offset
    pub fn generate_test_principal(id: u64) -> Principal {
        let thread_id = thread::current().id();
        let thread_hash = format!("{:?}", thread_id)
            .chars()
            .map(|c| c as u64)
            .fold(0u64, |acc, x| acc.wrapping_add(x));

        // Combine thread hash with the provided id for uniqueness
        let unique_id = thread_hash.wrapping_mul(1000000).wrapping_add(id);

        // Create principals from bytes to ensure they're valid
        let mut bytes = vec![0u8; 29];
        bytes[0] = (unique_id & 0xFF) as u8;
        bytes[1] = ((unique_id >> 8) & 0xFF) as u8;
        bytes[2] = ((unique_id >> 16) & 0xFF) as u8;
        bytes[3] = ((unique_id >> 24) & 0xFF) as u8;
        bytes[4] = ((unique_id >> 32) & 0xFF) as u8;
        bytes[5] = ((unique_id >> 40) & 0xFF) as u8;
        bytes[6] = ((unique_id >> 48) & 0xFF) as u8;
        bytes[7] = ((unique_id >> 56) & 0xFF) as u8;

        Principal::from_slice(&bytes)
    }

    /// Create test user metadata
    pub fn create_test_user_metadata(user_id: u64, canister_id: u64) -> UserMetadata {
        UserMetadata {
            user_canister_id: generate_test_principal(canister_id),
            user_name: format!("testuser{}", user_id),
            notification_key: None,
            is_migrated: false,
            email: None,
            signup_at: None,
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

    /// Generate a unique test key prefix for Redis operations
    pub fn generate_unique_test_key_prefix() -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let thread_id = thread::current().id();
        let thread_hash = format!("{:?}", thread_id)
            .chars()
            .map(|c| c as u64)
            .fold(0u64, |acc, x| acc.wrapping_add(x));

        let counter = PRINCIPAL_COUNTER.fetch_add(1, Ordering::SeqCst);

        format!("test_{}_{}_{}:", timestamp, thread_hash, counter)
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

    pub async fn cleanup_dragonfly_test_data(
        dragonfly_pool: &DragonflyPool,
        key_prefix: &str,
    ) -> Result<()> {
        use redis::AsyncCommands;

        let mut conn = dragonfly_pool.get_validated().await?;
        let pattern = format!("{}*", key_prefix);
        let keys: Vec<String> = conn.keys(&pattern).await?;

        if !keys.is_empty() {
            let _: () = conn.del(keys).await?;
        }

        Ok(())
    }

    /// Clean up test data for a specific principal
    pub async fn cleanup_test_principal_data(
        redis_pool: &RedisPool,
        principal: &Principal,
    ) -> Result<()> {
        use crate::utils::canister::CANISTER_TO_PRINCIPAL_KEY;
        use redis::AsyncCommands;

        let mut conn = redis_pool.get().await?;
        let principal_key = principal.to_text();

        // Clean up the principal's metadata
        let _: () = conn.del(&principal_key).await?;

        // Clean up any reverse index entries that might reference this principal
        let reverse_keys: Vec<String> = conn.hkeys(CANISTER_TO_PRINCIPAL_KEY).await?;
        for key in reverse_keys {
            let value: Option<String> = conn.hget(CANISTER_TO_PRINCIPAL_KEY, &key).await?;
            if let Some(value) = value {
                if value == principal_key {
                    let _: () = conn.hdel(CANISTER_TO_PRINCIPAL_KEY, &key).await?;
                }
            }
        }

        Ok(())
    }
}
