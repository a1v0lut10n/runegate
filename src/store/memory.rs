use super::{ChallengeStore, LinkStateStore, PreauthStore, RateLimitStore, SessionStore};

#[derive(Default)]
pub struct MemorySessionStore {
    // Inner state will be added as methods are defined
}

impl SessionStore for MemorySessionStore {}

#[derive(Default)]
pub struct MemoryPreauthStore {
}

impl PreauthStore for MemoryPreauthStore {}

#[derive(Default)]
pub struct MemoryLinkStateStore {
}

impl LinkStateStore for MemoryLinkStateStore {}

#[derive(Default)]
pub struct MemoryRateLimitStore {
}

impl RateLimitStore for MemoryRateLimitStore {}

#[derive(Default)]
pub struct MemoryChallengeStore {
}

impl ChallengeStore for MemoryChallengeStore {}
