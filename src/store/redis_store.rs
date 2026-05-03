use super::{
    ChallengeStore, LinkStateStore, PreauthStore, RateLimitStore, SessionStore, StoreError,
};
use redis::Client;

#[derive(Clone)]
pub struct RedisStore {
    pub client: Client,
}

impl RedisStore {
    pub fn new(redis_url: &str) -> Result<Self, StoreError> {
        let client =
            Client::open(redis_url).map_err(|e| StoreError::ConnectionError(e.to_string()))?;
        Ok(Self { client })
    }
}

impl SessionStore for RedisStore {}
impl PreauthStore for RedisStore {}
impl LinkStateStore for RedisStore {}
impl RateLimitStore for RedisStore {}
impl ChallengeStore for RedisStore {}
