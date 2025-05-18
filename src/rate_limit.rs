// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;
use std::sync::Mutex;
use std::collections::HashMap;

use lru::LruCache;
use std::num::NonZeroUsize;
use tracing::{info, warn};

/// Environment variable names for rate limiting configuration
pub const LOGIN_RATE_LIMIT_ENV: &str = "RUNEGATE_LOGIN_RATE_LIMIT";
pub const EMAIL_COOLDOWN_ENV: &str = "RUNEGATE_EMAIL_COOLDOWN";
pub const TOKEN_RATE_LIMIT_ENV: &str = "RUNEGATE_TOKEN_RATE_LIMIT";
pub const RATE_LIMIT_ENABLED_ENV: &str = "RUNEGATE_RATE_LIMIT_ENABLED";

/// Default rate limit values
pub const DEFAULT_LOGIN_RATE_LIMIT: u32 = 5; // 5 attempts per minute per IP
pub const DEFAULT_EMAIL_COOLDOWN: u64 = 300; // 5 minutes (300 seconds) cooldown per email
pub const DEFAULT_TOKEN_RATE_LIMIT: u32 = 10; // 10 token verification attempts per minute per IP

/// Configuration for all rate limiting mechanisms
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Number of login attempts allowed per minute per IP
    pub login_rate_limit: u32,
    /// Cooldown period in seconds for sending magic links to the same email
    pub email_cooldown: u64,
    /// Number of token verification attempts allowed per minute per IP
    pub token_rate_limit: u32,
    /// Whether rate limiting is enabled
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login_rate_limit: DEFAULT_LOGIN_RATE_LIMIT,
            email_cooldown: DEFAULT_EMAIL_COOLDOWN,
            token_rate_limit: DEFAULT_TOKEN_RATE_LIMIT,
            enabled: true,
        }
    }
}

impl RateLimitConfig {
    /// Load rate limit configuration from environment variables or use defaults
    pub fn from_env() -> Self {
        let login_rate_limit = std::env::var(LOGIN_RATE_LIMIT_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_LOGIN_RATE_LIMIT);

        let email_cooldown = std::env::var(EMAIL_COOLDOWN_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_EMAIL_COOLDOWN);

        let token_rate_limit = std::env::var(TOKEN_RATE_LIMIT_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_TOKEN_RATE_LIMIT);

        let enabled = std::env::var(RATE_LIMIT_ENABLED_ENV)
            .map(|v| v.to_lowercase() != "false" && v != "0")
            .unwrap_or(true);

        Self {
            login_rate_limit,
            email_cooldown,
            token_rate_limit,
            enabled,
        }
    }
}

/// Simple timestamp for rate limiting
#[derive(Debug, Clone, Copy)]
struct Timestamp(std::time::SystemTime);

impl Timestamp {
    fn now() -> Self {
        Timestamp(std::time::SystemTime::now())
    }
    
    fn elapsed(&self) -> Duration {
        self.0.elapsed().unwrap_or_else(|_| Duration::from_secs(0))
    }
}

/// Email rate limiter to enforce cooldown periods between sending magic links
/// to the same email address
pub struct EmailRateLimiter {
    /// LRU cache that maps email addresses to last request timestamps
    cache: Mutex<LruCache<String, Timestamp>>,
    /// Cooldown period between requests for the same email
    cooldown: Duration,
    /// Whether rate limiting is enabled
    enabled: bool,
}

impl EmailRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        // Create an LRU cache with a reasonable capacity
        let cache = Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap()));
        let cooldown = Duration::from_secs(config.email_cooldown);

        Self {
            cache,
            cooldown,
            enabled: config.enabled,
        }
    }

    /// Check if an email is allowed to receive a magic link
    /// Returns Some(remaining_seconds) if rate-limited, None if allowed
    pub fn check_email(&self, email: &str) -> Option<u64> {
        if !self.enabled {
            return None;
        }

        let now = Timestamp::now();
        let mut cache = self.cache.lock().unwrap();

        if let Some(last_time) = cache.get(email) {
            let elapsed = last_time.elapsed();
            if elapsed < self.cooldown {
                let remaining = self.cooldown.saturating_sub(elapsed);
                return Some(remaining.as_secs());
            }
        }

        // Update the last request time for this email
        cache.put(email.to_string(), now);
        None
    }
}

/// A simple rate limiter for login attempts using a HashMap to track counts
pub struct LoginRateLimiter {
    /// Maps IP -> (count, last_reset_time)
    attempts: Mutex<HashMap<String, (u32, Timestamp)>>,
    /// Maximum attempts allowed per minute
    max_attempts: u32,
    /// Reset period (typically 1 minute)
    period: Duration,
    /// Whether rate limiting is enabled
    enabled: bool,
}

impl LoginRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts: config.login_rate_limit,
            period: Duration::from_secs(60), // 1 minute
            enabled: config.enabled,
        }
    }
    
    /// Check if an IP address is allowed to make a login attempt
    /// Returns true if allowed, false if rate-limited
    pub fn check_ip(&self, ip: &str) -> bool {
        if !self.enabled {
            return true;
        }
        
        let now = Timestamp::now();
        let mut attempts = self.attempts.lock().unwrap();
        
        let entry = attempts.entry(ip.to_string()).or_insert((0, now));
        
        // If the period has elapsed, reset the counter
        if entry.1.elapsed() >= self.period {
            *entry = (1, now); // Reset with this attempt counted
            return true;
        }
        
        // Check if we're under the limit
        if entry.0 < self.max_attempts {
            entry.0 += 1;
            true
        } else {
            warn!("Rate limited login attempt from IP: {}", ip);
            false
        }
    }
}

/// Rate limiter for token verification attempts
pub struct TokenRateLimiter {
    /// Maps IP -> (count, last_reset_time)
    attempts: Mutex<HashMap<String, (u32, Timestamp)>>,
    /// Maximum attempts allowed per minute
    max_attempts: u32,
    /// Reset period (typically 1 minute)
    period: Duration,
    /// Whether rate limiting is enabled
    enabled: bool,
}

impl TokenRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts: config.token_rate_limit,
            period: Duration::from_secs(60), // 1 minute
            enabled: config.enabled,
        }
    }
    
    /// Check if an IP address is allowed to make a token verification attempt
    /// Returns true if allowed, false if rate-limited
    pub fn check_ip(&self, ip: &str) -> bool {
        if !self.enabled {
            return true;
        }
        
        let now = Timestamp::now();
        let mut attempts = self.attempts.lock().unwrap();
        
        let entry = attempts.entry(ip.to_string()).or_insert((0, now));
        
        // If the period has elapsed, reset the counter
        if entry.1.elapsed() >= self.period {
            *entry = (1, now); // Reset with this attempt counted
            return true;
        }
        
        // Check if we're under the limit
        if entry.0 < self.max_attempts {
            entry.0 += 1;
            true
        } else {
            warn!("Rate limited token verification attempt from IP: {}", ip);
            false
        }
    }
}

/// Global rate limiters container singleton
pub struct RateLimiters {
    pub email_limiter: EmailRateLimiter,
    pub login_limiter: LoginRateLimiter,
    pub token_limiter: TokenRateLimiter,
    pub config: RateLimitConfig,
}

impl RateLimiters {
    pub fn new() -> Self {
        let config = RateLimitConfig::from_env();
        
        info!("Rate limiting configuration:");
        info!("  Enabled: {}", config.enabled);
        info!("  Login rate limit: {} per minute per IP", config.login_rate_limit);
        info!("  Email cooldown: {} seconds per email", config.email_cooldown);
        info!("  Token rate limit: {} per minute per IP", config.token_rate_limit);
        
        let email_limiter = EmailRateLimiter::new(&config);
        let login_limiter = LoginRateLimiter::new(&config);
        let token_limiter = TokenRateLimiter::new(&config);
        
        Self {
            email_limiter,
            login_limiter,
            token_limiter,
            config,
        }
    }
}
