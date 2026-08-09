use crate::memory_session_store::MemorySessionStore;
use actix_session::storage::{LoadError, SaveError, SessionKey, SessionStore, UpdateError};
use actix_web::cookie::time::Duration;
use std::collections::HashMap;

use actix_session::storage::RedisSessionStore;

/// A dynamic session store that can wrap either the default in-memory store
/// or a Redis-backed store for distributed deployments in magic-link-only mode.
#[derive(Clone)]
pub enum RunegateSessionStore {
    Memory(MemorySessionStore),
    Redis(RedisSessionStore),
}

impl SessionStore for RunegateSessionStore {
    async fn load(
        &self,
        session_key: &SessionKey,
    ) -> Result<Option<HashMap<String, String>>, LoadError> {
        match self {
            Self::Memory(store) => store.load(session_key).await,
            Self::Redis(store) => store.load(session_key).await,
        }
    }

    async fn save(
        &self,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        match self {
            Self::Memory(store) => store.save(session_state, ttl).await,
            Self::Redis(store) => store.save(session_state, ttl).await,
        }
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        match self {
            Self::Memory(store) => store.update(session_key, session_state, ttl).await,
            Self::Redis(store) => store.update(session_key, session_state, ttl).await,
        }
    }

    async fn update_ttl(
        &self,
        session_key: &SessionKey,
        ttl: &Duration,
    ) -> Result<(), anyhow::Error> {
        match self {
            Self::Memory(store) => store.update_ttl(session_key, ttl).await,
            Self::Redis(store) => store.update_ttl(session_key, ttl).await,
        }
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        match self {
            Self::Memory(store) => store.delete(session_key).await,
            Self::Redis(store) => store.delete(session_key).await,
        }
    }
}
