use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    dragonfly::DragonflyPool,
    utils::error::{Error, Result},
};
use redis::AsyncCommands;

const BATCH_SIZE: usize = 200;

/// Abstraction over the hash-map operations needed by the API implementation.
/// Implemented by `Arc<DragonflyPool>` (production) and `MockMetadataKvStore` (tests).
pub trait MetadataKvStore: Send + Sync {
    /// Get a single field from a hash.
    async fn hget(&self, key: &str, field: &str) -> Result<Option<Vec<u8>>>;

    /// Set a field in a hash.
    async fn hset(&self, key: &str, field: &str, value: &[u8]) -> Result<()>;

    /// Set a field only if it does not already exist. Returns `true` if inserted.
    async fn hset_nx(&self, key: &str, field: &str, value: &[u8]) -> Result<bool>;

    /// Delete a single field from a hash.
    async fn hdel(&self, key: &str, field: &str) -> Result<()>;

    /// Get the same field from multiple hash keys (pipeline in real Redis).
    async fn hget_bulk(&self, keys: &[String], field: &str) -> Result<Vec<Option<Vec<u8>>>>;

    /// Delete multiple top-level keys (pipeline in real Redis).
    async fn del_bulk(&self, keys: &[String]) -> Result<()>;

    /// Delete multiple fields from a single hash.
    async fn hdel_bulk(&self, key: &str, fields: &[String]) -> Result<()>;

    /// Get multiple fields from a single hash; values are decoded as UTF-8 strings.
    async fn hmget(&self, key: &str, fields: &[String]) -> Result<Vec<Option<String>>>;
}

// ── Arc<DragonflyPool> implementation ────────────────────────────────────────

impl MetadataKvStore for Arc<DragonflyPool> {
    async fn hget(&self, key: &str, field: &str) -> Result<Option<Vec<u8>>> {
        let key = key.to_string();
        let field = field.to_string();
        self.execute_with_retry(|mut conn| {
            let key = key.clone();
            let field = field.clone();
            async move { conn.hget(key, field).await }
        })
        .await
        .map_err(Error::from)
    }

    async fn hset(&self, key: &str, field: &str, value: &[u8]) -> Result<()> {
        let key = key.to_string();
        let field = field.to_string();
        let value = value.to_vec();
        self.execute_with_retry(|mut conn| {
            let key = key.clone();
            let field = field.clone();
            let value = value.clone();
            async move {
                let _: bool = conn.hset(key, field, value).await?;
                Ok(())
            }
        })
        .await
        .map_err(Error::from)
    }

    async fn hset_nx(&self, key: &str, field: &str, value: &[u8]) -> Result<bool> {
        let key = key.to_string();
        let field = field.to_string();
        let value = value.to_vec();
        self.execute_with_retry(|mut conn| {
            let key = key.clone();
            let field = field.clone();
            let value = value.clone();
            async move {
                let inserted: usize = conn.hset_nx(key, field, value).await?;
                Ok(inserted == 1)
            }
        })
        .await
        .map_err(Error::from)
    }

    async fn hdel(&self, key: &str, field: &str) -> Result<()> {
        let key = key.to_string();
        let field = field.to_string();
        self.execute_with_retry(|mut conn| {
            let key = key.clone();
            let field = field.clone();
            async move {
                let _: usize = conn.hdel(key, field).await?;
                Ok(())
            }
        })
        .await
        .map_err(Error::from)
    }

    async fn hget_bulk(&self, keys: &[String], field: &str) -> Result<Vec<Option<Vec<u8>>>> {
        if keys.is_empty() {
            return Ok(vec![]);
        }
        let keys = keys.to_vec();
        let field = field.to_string();
        let mut results = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(BATCH_SIZE) {
            let chunk = chunk.to_vec();
            let field = field.clone();
            let chunk_results: Vec<Option<Vec<u8>>> = self
                .execute_with_retry(|mut conn| {
                    let chunk = chunk.clone();
                    let field = field.clone();
                    async move {
                        let mut pipe = redis::pipe();
                        for key in &chunk {
                            pipe.hget(key, &field);
                        }
                        pipe.query_async(&mut conn).await
                    }
                })
                .await
                .map_err(Error::from)?;
            results.extend(chunk_results);
        }
        Ok(results)
    }

    async fn del_bulk(&self, keys: &[String]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let keys = keys.to_vec();
        for chunk in keys.chunks(BATCH_SIZE) {
            let chunk = chunk.to_vec();
            self.execute_with_retry(|mut conn| {
                let chunk = chunk.clone();
                async move {
                    let mut pipe = redis::pipe();
                    pipe.del(&chunk).ignore();
                    pipe.query_async::<()>(&mut conn).await
                }
            })
            .await
            .map_err(Error::from)?;
        }
        Ok(())
    }

    async fn hdel_bulk(&self, key: &str, fields: &[String]) -> Result<()> {
        if fields.is_empty() {
            return Ok(());
        }
        let key = key.to_string();
        let fields = fields.to_vec();
        for chunk in fields.chunks(BATCH_SIZE) {
            let chunk = chunk.to_vec();
            let key = key.clone();
            self.execute_with_retry(|mut conn| {
                let key = key.clone();
                let chunk = chunk.clone();
                async move {
                    let _: usize = conn.hdel(key, chunk).await?;
                    Ok(())
                }
            })
            .await
            .map_err(Error::from)?;
        }
        Ok(())
    }

    async fn hmget(&self, key: &str, fields: &[String]) -> Result<Vec<Option<String>>> {
        if fields.is_empty() {
            return Ok(vec![]);
        }
        let key = key.to_string();
        let fields = fields.to_vec();
        let mut results = Vec::with_capacity(fields.len());
        for chunk in fields.chunks(BATCH_SIZE) {
            let chunk = chunk.to_vec();
            let key = key.clone();
            let chunk_results: Vec<Option<String>> = self
                .execute_with_retry(|mut conn| {
                    let key = key.clone();
                    let chunk = chunk.clone();
                    async move { conn.hmget(key, chunk).await }
                })
                .await
                .map_err(Error::from)?;
            results.extend(chunk_results);
        }
        Ok(results)
    }
}

// ── MockMetadataKvStore ───────────────────────────────────────────────────────

/// In-memory store for use in unit tests. No real Redis connection required.
pub struct MockMetadataKvStore {
    /// `outer key → (field → bytes)`
    pub data: Arc<RwLock<HashMap<String, HashMap<String, Vec<u8>>>>>,
}

impl MockMetadataKvStore {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Pre-populate a hash field (for test setup).
    pub async fn insert(&self, key: &str, field: &str, value: Vec<u8>) {
        self.data
            .write()
            .await
            .entry(key.to_string())
            .or_default()
            .insert(field.to_string(), value);
    }

    /// Read back a stored field (for test assertions).
    pub async fn get_raw(&self, key: &str, field: &str) -> Option<Vec<u8>> {
        self.data
            .read()
            .await
            .get(key)
            .and_then(|h| h.get(field))
            .cloned()
    }

    /// True if the outer key exists (even if its hash is empty).
    pub async fn key_exists(&self, key: &str) -> bool {
        self.data.read().await.contains_key(key)
    }
}

impl MetadataKvStore for MockMetadataKvStore {
    async fn hget(&self, key: &str, field: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .data
            .read()
            .await
            .get(key)
            .and_then(|h| h.get(field))
            .cloned())
    }

    async fn hset(&self, key: &str, field: &str, value: &[u8]) -> Result<()> {
        self.data
            .write()
            .await
            .entry(key.to_string())
            .or_default()
            .insert(field.to_string(), value.to_vec());
        Ok(())
    }

    async fn hset_nx(&self, key: &str, field: &str, value: &[u8]) -> Result<bool> {
        let mut data = self.data.write().await;
        let hash = data.entry(key.to_string()).or_default();
        if hash.contains_key(field) {
            Ok(false)
        } else {
            hash.insert(field.to_string(), value.to_vec());
            Ok(true)
        }
    }

    async fn hdel(&self, key: &str, field: &str) -> Result<()> {
        if let Some(hash) = self.data.write().await.get_mut(key) {
            hash.remove(field);
        }
        Ok(())
    }

    async fn hget_bulk(&self, keys: &[String], field: &str) -> Result<Vec<Option<Vec<u8>>>> {
        let data = self.data.read().await;
        Ok(keys
            .iter()
            .map(|k| data.get(k).and_then(|h| h.get(field)).cloned())
            .collect())
    }

    async fn del_bulk(&self, keys: &[String]) -> Result<()> {
        let mut data = self.data.write().await;
        for key in keys {
            data.remove(key);
        }
        Ok(())
    }

    async fn hdel_bulk(&self, key: &str, fields: &[String]) -> Result<()> {
        if let Some(hash) = self.data.write().await.get_mut(key) {
            for field in fields {
                hash.remove(field);
            }
        }
        Ok(())
    }

    async fn hmget(&self, key: &str, fields: &[String]) -> Result<Vec<Option<String>>> {
        let data = self.data.read().await;
        let hash = data.get(key);
        Ok(fields
            .iter()
            .map(|f| {
                hash.and_then(|h| h.get(f))
                    .and_then(|v| String::from_utf8(v.clone()).ok())
            })
            .collect())
    }
}
