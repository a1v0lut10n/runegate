use runegate::auth::{create_token, verify_token};
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
    
    match action.as_ref() {
        "create" => {
            // Create a token with 15 minutes expiry
            let token = create_token(email, 15);
            
            println!("✅ JWT Token generated for {}", email);
            println!("\nToken: {}", token);
            
            // Generate auth URL for testing
            let auth_url = format!("http://localhost:7870/auth?token={}", token);
            println!("\n🔐 Authentication URL:");
            println!("{}", auth_url);
            
            println!("\n📋 For testing with curl:");
            println!("curl -v \"{}\"", auth_url);
            println!("\n⚠️ Note: This token will expire in 15 minutes.");
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
