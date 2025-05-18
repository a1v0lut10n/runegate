// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;
use std::thread;
use runegate::rate_limit::{
    RateLimitConfig, 
    EmailRateLimiter,
    LoginRateLimiter,
    TokenRateLimiter
};

#[test]
fn test_email_rate_limiter() {
    // Create a test config
    let config = RateLimitConfig {
        login_rate_limit: 5,
        email_cooldown: 2, // short cooldown for testing (2 seconds)
        token_rate_limit: 10,
        enabled: true,
    };

    let email_limiter = EmailRateLimiter::new(&config);
    let test_email = "test@example.com";

    // First request should be allowed
    assert!(email_limiter.check_email(test_email).is_none());
    
    // Second immediate request should be rate limited
    let cooldown = email_limiter.check_email(test_email);
    assert!(cooldown.is_some());
    assert!(cooldown.unwrap() > 0);
    
    // Wait for cooldown to expire
    thread::sleep(Duration::from_secs(3));
    
    // Should be allowed again
    assert!(email_limiter.check_email(test_email).is_none());
}

#[test]
fn test_login_rate_limiter() {
    // Create a test config
    let config = RateLimitConfig {
        login_rate_limit: 3, // only allow 3 attempts
        email_cooldown: 300,
        token_rate_limit: 10, 
        enabled: true,
    };

    let login_limiter = LoginRateLimiter::new(&config);
    let test_ip = "192.168.1.1";
    
    // First three attempts should be allowed
    assert!(login_limiter.check_ip(test_ip));
    assert!(login_limiter.check_ip(test_ip));
    assert!(login_limiter.check_ip(test_ip));
    
    // Fourth attempt should be blocked
    assert!(!login_limiter.check_ip(test_ip));
    
    // Different IP should still be allowed
    assert!(login_limiter.check_ip("192.168.1.2"));
    
    // Check that disabling works
    let disabled_config = RateLimitConfig {
        enabled: false,
        ..config
    };
    let disabled_limiter = LoginRateLimiter::new(&disabled_config);
    
    // Even excessive attempts should be allowed when disabled
    for _ in 0..10 {
        assert!(disabled_limiter.check_ip(test_ip));
    }
}

#[test]
fn test_token_rate_limiter() {
    // Create a test config
    let config = RateLimitConfig {
        login_rate_limit: 5,
        email_cooldown: 300,
        token_rate_limit: 4, // only allow 4 attempts
        enabled: true,
    };

    let token_limiter = TokenRateLimiter::new(&config);
    let test_ip = "192.168.1.1";
    
    // First four attempts should be allowed
    assert!(token_limiter.check_ip(test_ip));
    assert!(token_limiter.check_ip(test_ip));
    assert!(token_limiter.check_ip(test_ip));
    assert!(token_limiter.check_ip(test_ip));
    
    // Fifth attempt should be blocked
    assert!(!token_limiter.check_ip(test_ip));
}
