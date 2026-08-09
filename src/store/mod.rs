use std::fmt::Display;

pub mod memory;
pub mod pg;
pub mod session;

#[derive(Debug)]
pub enum StoreError {
    NotFound,
    ConnectionError(String),
    SerializationError(String),
    Other(String),
}

impl std::error::Error for StoreError {}
impl Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NotFound => write!(f, "Record not found in store"),
            StoreError::ConnectionError(e) => write!(f, "Store connection error: {}", e),
            StoreError::SerializationError(e) => write!(f, "Store serialization error: {}", e),
            StoreError::Other(e) => write!(f, "Store error: {}", e),
        }
    }
}

// These traits will be fleshed out with methods as we migrate each component.
// For now, they serve as the foundational types for Phase 1.

pub trait SessionStore: Send + Sync {}

pub trait PreauthStore: Send + Sync {}

pub trait LinkStateStore: Send + Sync {}

pub trait RateLimitStore: Send + Sync {}

pub trait ChallengeStore: Send + Sync {}
