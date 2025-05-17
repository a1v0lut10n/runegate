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
            let payload = json!({
                "email": "test@example.com",
            });

            // Make multiple requests quickly (default limit is 5 per minute)
            let mut responses = vec![];
            println!("Making multiple login requests to trigger rate limiting...");

            for i in 0..7 {
                let res = client.post(&url)
                    .json(&payload)
                    .send()
                    .await
                    .unwrap();
                
                let status = res.status().as_u16();
                println!("Request {}: Status {}", i+1, status);
                responses.push(status);
            }
            
            // We should have some 200 OKs followed by 429 Too Many Requests
            let ok_count = responses.iter().filter(|&status| *status == 200).count();
            let rate_limited_count = responses.iter().filter(|&status| *status == 429).count();
            
            println!("OK responses: {}, Rate limited: {}", ok_count, rate_limited_count);
            assert!(ok_count > 0, "Some requests should succeed");
            assert!(rate_limited_count > 0, "Some requests should be rate limited");
            assert_eq!(ok_count + rate_limited_count, 7);
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
            let email = "test@example.com";
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
            
            // Should return rate limit info in header
            assert!(res2.headers().contains_key("x-ratelimit-reset"));
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
            let payload = json!({ "email": "test@example.com" });
            
            println!("With rate limiting disabled, all requests should succeed...");
            
            // Make multiple requests that would normally trigger rate limiting
            let mut success_count = 0;
            for i in 0..10 {
                let res = client.post(&url)
                    .json(&payload)
                    .send()
                    .await
                    .unwrap();
                
                if res.status().as_u16() == 200 {
                    success_count += 1;
                }
                
                println!("Request {}: Status {}", i+1, res.status().as_u16());
            }
            
            // All should succeed if rate limiting is disabled
            assert_eq!(success_count, 10, "All requests should succeed when rate limiting is disabled");
        });
    }
}
