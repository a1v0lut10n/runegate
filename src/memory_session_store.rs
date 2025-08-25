// SPDX-License-Identifier: Apache-2.0
use actix_session::storage::{LoadError, SaveError, SessionKey, SessionStore, UpdateError};
use actix_web::cookie::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct MemorySessionStore {
    sessions: Arc<RwLock<HashMap<String, HashMap<String, String>>>>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for MemorySessionStore {
    async fn load(&self, session_key: &SessionKey) -> Result<Option<HashMap<String, String>>, LoadError> {
        let key = session_key.as_ref();
        info!("[MEMORY_STORE - LOAD] Loading session data for key: {}", key);
        
        match self.sessions.read() {
            Ok(sessions) => {
                info!("[MEMORY_STORE - LOAD] Available session keys: {:?}", sessions.keys().collect::<Vec<_>>());
                let result = sessions.get(key).cloned();
                info!("[MEMORY_STORE - LOAD] Session data loaded for key '{}': {:?} entries", key, result.as_ref().map(|s| s.len()));
                if result.is_none() {
                    info!("[MEMORY_STORE - LOAD] Session key '{}' not found in store", key);
                }
                Ok(result)
            }
            Err(e) => {
                error!("Failed to acquire read lock: {}", e);
                Err(LoadError::Other(anyhow::anyhow!("Failed to acquire read lock: {}", e)))
            }
        }
    }

    async fn save(
        &self,
        session_data: HashMap<String, String>,
        _ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        // Use the session framework's key generation instead of our own
        let key_string = Uuid::new_v4().to_string();
        let session_key = SessionKey::try_from(key_string.clone())
            .map_err(|e| SaveError::Other(anyhow::anyhow!("Failed to create SessionKey: {}", e)))?;
        
        let key_for_storage = session_key.as_ref();
        info!("[MEMORY_STORE - SAVE] Saving session data for key: {}, entries: {}", key_for_storage, session_data.len());
        
        match self.sessions.write() {
            Ok(mut sessions) => {
                sessions.insert(key_for_storage.to_string(), session_data);
                info!("[MEMORY_STORE - SAVE] Session data saved successfully for key: {}", key_for_storage);
                Ok(session_key)
            }
            Err(e) => {
                error!("Failed to acquire write lock: {}", e);
                Err(SaveError::Other(anyhow::anyhow!("Failed to acquire write lock: {}", e)))
            }
        }
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_data: HashMap<String, String>,
        _ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        let key = session_key.as_ref();
        info!("[MEMORY_STORE - UPDATE] Updating session data for key: {}, entries: {}", key, session_data.len());
        
        match self.sessions.write() {
            Ok(mut sessions) => {
                sessions.insert(key.to_string(), session_data);
                info!("[MEMORY_STORE - UPDATE] Session data updated successfully for key: {}", key);
                Ok(session_key)
            }
            Err(e) => {
                error!("Failed to acquire write lock: {}", e);
                Err(UpdateError::Other(anyhow::anyhow!("Failed to acquire write lock: {}", e)))
            }
        }
    }

    async fn update_ttl(&self, _session_key: &SessionKey, _ttl: &Duration) -> Result<(), anyhow::Error> {
        // In-memory store doesn't need to update TTL since sessions live for the process lifetime
        Ok(())
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        let key = session_key.as_ref();
        debug!("Deleting session data for key: {}", key);
        
        match self.sessions.write() {
            Ok(mut sessions) => {
                let removed = sessions.remove(key);
                debug!("Session deletion result for key {}: {:?}", key, removed.is_some());
                Ok(())
            }
            Err(e) => {
                error!("Failed to acquire write lock for deletion: {}", e);
                Err(anyhow::anyhow!("Failed to acquire write lock: {}", e))
            }
        }
    }
}
