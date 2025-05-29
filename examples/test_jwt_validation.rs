// SPDX-License-Identifier: Apache-2.0
use runegate::auth::{create_token, verify_token, get_jwt_secret};
use std::env;

// A simple test script to generate and validate JWT tokens for testing
fn main() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: cargo run --example test_jwt_validation <email> [action]");
        println!("Actions:");
        println!("  - create: Generate a token for the email (default)");
        println!("  - verify: Verify a token");
        return;
    }
    
    let email = &args[1];
    let action = if args.len() > 2 { &args[2] } else { "create" };
    
    // Print JWT secret info for debugging
    let secret = get_jwt_secret();
    println!("DEBUG: Using JWT secret length: {} bytes", secret.len());
    
    match action.as_ref() {
        "create" => {
            // Create a token with 15 minutes expiry
            match create_token(email, 15) {
                Ok(token) => {
                    println!("✅ JWT Token generated for {}", email);
                    println!("\nToken: {}", token);
                    
                    // Generate auth URL for testing
                    let auth_url = format!("http://localhost:7870/auth?token={}", token);
                    println!("\n🔐 Authentication URL:");
                    println!("{}", auth_url);
                    
                    println!("\n📋 For testing with curl:");
                    println!("curl -v \"{}\"", auth_url);
                    println!("\n⚠️ Note: This token will expire in 15 minutes.");
                    
                    // Immediately verify the token for debugging
                    println!("\n🔍 Attempting immediate verification:");
                    match verify_token(&token) {
                        Ok(verified_email) => {
                            println!("  ✅ Token verified! Email: {}", verified_email);
                        },
                        Err(e) => {
                            println!("  ❌ Verification failed: {}", e);
                        }
                    }
                },
                Err(err) => {
                    println!("❌ Error generating token: {}", err);
                }
            }
        },
        "verify" => {
            if args.len() < 3 {
                println!("Error: Token required for verification");
                return;
            }
            
            let token = &args[2];
            
            match verify_token(token) {
                Ok(email) => {
                    println!("✅ Token is valid for user: {}", email);
                },
                Err(e) => {
                    println!("❌ Invalid token: {}", e);
                }
            }
        },
        _ => {
            println!("Unknown action: {}", action);
        }
    }
}
