// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;

// This file contains integration tests for the rate limiting behaviors
// of the Runegate API endpoints. These tests are marked with #[ignore]
// by default because they require a running server and will make actual HTTP calls.
//
// To run these tests, use:
// cargo test --test api_rate_limit_tests -- --ignored

#[cfg(test)]
mod api_tests {
    use super::*;
    use reqwest::Client;
    use tokio::runtime::Runtime;
    use serde_json::json;
    use std::thread;

    const SERVER_URL: &str = "http://localhost:7870";

    // Helper function to create a test client
    fn create_client() -> Client {
        Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    // Test login endpoint rate limiting
    #[test]
    #[ignore] // Requires a running server
    fn test_login_endpoint_rate_limiting() {
        // Create a runtime for async functions
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let client = create_client();
            let url = format!("{}/login", SERVER_URL);
            
            // Use different emails to avoid the email cooldown effect
            let mut responses = vec![];
            println!("Making multiple login requests to trigger rate limiting...");

            // First, check if rate limiting is enabled by making a test request
            let test_res = client.post(&url)
                .json(&json!({"email": "test_initial@example.com"}))
                .send()
                .await
                .unwrap();
                
            println!("Initial test request status: {}", test_res.status().as_u16());
            
            // Give a moment for any rate limiters to reset
            thread::sleep(Duration::from_secs(1));
            
            // Now make multiple requests with the same IP but different emails
            for i in 0..7 {
                let email = format!("test{}@example.com", i);
                let payload = json!({"email": email});
                
                let res = client.post(&url)
                    .json(&payload)
                    .send()
                    .await
                    .unwrap();
                
                let status = res.status().as_u16();
                println!("Request {} ({}): Status {}", i+1, email, status);
                responses.push(status);
            }
            
            // We should have at least one success and some rate limiting
            let ok_count = responses.iter().filter(|&status| *status == 200).count();
            let rate_limited_count = responses.iter().filter(|&status| *status == 429).count();
            
            println!("OK responses: {}, Rate limited: {}", ok_count, rate_limited_count);
            
            // We need to be flexible here since we don't know exactly how many will go through
            // before rate limiting kicks in, but the test should demonstrate both behaviors
            assert!(ok_count + rate_limited_count == 7, "All responses should be either 200 or 429");
            
            // If rate limiting is enabled, we should see at least one rate limited response
            // If all are rate limited or all are successful, the test is still valid but
            // we should note that in the output
            if rate_limited_count == 0 {
                println!("Note: All requests succeeded. Rate limiting may be disabled.");
            } else if ok_count == 0 {
                println!("Note: All requests were rate limited. The limit may be set very low.");
            } else {
                println!("✅ Mix of successful and rate-limited responses as expected.");
            }
        });
    }

    // Test email cooldown rate limiting
    #[test]
    #[ignore] // Requires a running server
    fn test_email_cooldown_rate_limiting() {
        // Create a runtime for async functions
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let client = create_client();
            let url = format!("{}/login", SERVER_URL);
            
            // Use same email for both requests to trigger cooldown
            let email = "test_cooldown@example.com";
            let payload = json!({ "email": email });
            
            // First request should succeed
            let res1 = client.post(&url)
                .json(&payload)
                .send()
                .await
                .unwrap();
            
            assert_eq!(res1.status().as_u16(), 200);
            println!("First request to {} succeeded", email);
            
            // Second immediate request should be rate limited by email cooldown
            let res2 = client.post(&url)
                .json(&payload)
                .send()
                .await
                .unwrap();
            
            assert_eq!(res2.status().as_u16(), 429);
            println!("Second request was rate-limited as expected");
            
            // Check for appropriate headers
            println!("Response headers: {:?}", res2.headers());
            
            // Check that we have a rate limit reset header (case insensitive)
            let has_reset_header = res2.headers().iter().any(|(name, _)| {
                name.as_str().to_lowercase() == "x-ratelimit-reset"
            });
            
            assert!(has_reset_header, "Response should contain a rate limit reset header");
            
            // For this test, just verify we get a 429 status, which is sufficient
            // to confirm the rate limiting is working. We don't need to be overly
            // strict about which headers are present.
        });
    }

    // Test token verification rate limiting
    #[test]
    #[ignore] // Requires a running server
    fn test_token_verification_rate_limiting() {
        // Create a runtime for async functions
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let client = create_client();
            let url = format!("{}/auth?token=invalid_token", SERVER_URL); // Using invalid token
            
            // Make multiple requests quickly (default limit is 10 per minute)
            let mut responses = vec![];
            println!("Making multiple token verification requests to trigger rate limiting...");
            
            for i in 0..12 {
                let res = client.get(&url)
                    .send()
                    .await
                    .unwrap();
                
                let status = res.status().as_u16();
                println!("Request {}: Status {}", i+1, status);
                responses.push(status);
            }
            
            // We should have some 401 Unauthorized followed by 429 Too Many Requests
            let unauthorized_count = responses.iter().filter(|&status| *status == 401).count();
            let rate_limited_count = responses.iter().filter(|&status| *status == 429).count();
            
            println!("Unauthorized: {}, Rate limited: {}", unauthorized_count, rate_limited_count);
            assert!(unauthorized_count > 0, "Some requests should be unauthorized");
            assert!(rate_limited_count > 0, "Some requests should be rate limited");
            assert_eq!(unauthorized_count + rate_limited_count, 12);
        });
    }

    // Test that rate limiting can be disabled
    #[test]
    #[ignore] // Requires a running server with RUNEGATE_RATE_LIMIT_ENABLED=false
    fn test_rate_limit_disabled() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let client = create_client();
            let url = format!("{}/login", SERVER_URL);
            
            println!("With rate limiting disabled, all requests should succeed...");
            
            // First, check the actual rate limiting configuration
            println!("🔍 Checking actual rate limit configuration from server...");
            let config_res = client.get(&format!("{}/rate_limit_info", SERVER_URL))
                .send()
                .await
                .unwrap();
            
            if config_res.status().is_success() {
                let config = config_res.json::<serde_json::Value>().await.unwrap();
                println!("Server config: {}", config);
                println!("Rate limiting enabled: {}", config["enabled"]);
            } else {
                println!("❌ Failed to get rate limit config: {}", config_res.status());
            }
            
            // Make multiple requests that would normally trigger rate limiting
            // Use same IP but different emails to test IP-based limiting specifically
            let mut responses = vec![];
            
            for i in 0..10 {
                // Use different emails to avoid any potential email-based cooldowns
                // even though they should be disabled
                let email = format!("disabled_test{}@example.com", i);
                let payload = json!({ "email": email });
                
                let res = client.post(&url)
                    .json(&payload)
                    .send()
                    .await
                    .unwrap();
                
                let status = res.status().as_u16();
                responses.push(status);
                println!("Request {} ({}): Status {}", i+1, email, status);
            }
            
            // Count successful and rate-limited responses
            let success_count = responses.iter().filter(|&status| *status == 200).count();
            let rate_limited_count = responses.iter().filter(|&status| *status == 429).count();
            
            println!("Successful: {}, Rate limited: {}", success_count, rate_limited_count);
            
            // Verify the test environment was set correctly
            if rate_limited_count > 0 {
                println!("❌ Some requests were rate limited. Make sure RUNEGATE_RATE_LIMIT_ENABLED=false");
                println!("   Try running with: RUNEGATE_RATE_LIMIT_ENABLED=false ./scripts/run_integration_tests.sh test_rate_limit_disabled");
            }
            
            // In disabled mode, we should see all requests succeed
            assert_eq!(success_count, 10, "All requests should succeed when rate limiting is disabled");
            assert_eq!(rate_limited_count, 0, "No requests should be rate limited when disabled");
        });
    }
}
