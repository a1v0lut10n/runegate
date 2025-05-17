use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, errors::Error as JwtError};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::instrument;

// Environment variable name for JWT secret
pub const JWT_SECRET_ENV: &str = "RUNEGATE_JWT_SECRET";
// Default secret if not set in environment (only for development)
const DEFAULT_SECRET: &[u8] = b"runegate_dev_only_secret_please_change_in_production";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,   // The subject (usually email)
    pub exp: usize,    // Expiration time
    pub iat: usize,    // Issued at time
}

/// Creates a JWT token for a user
#[instrument(fields(email = %email, expiry_minutes = %expiry_minutes))]
pub fn create_token(email: &str, expiry_minutes: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;
    
    // Token expires after the specified minutes
    let expiration = now + (60 * expiry_minutes as usize);
    
    let claims = Claims { 
        sub: email.to_owned(), 
        exp: expiration,
        iat: now,
    };
    
    let secret = get_jwt_secret();
    encode(&Header::default(), &claims, &EncodingKey::from_secret(&secret))
        .expect("Failed to create token")
}

/// Verifies a JWT token and returns the user's email if valid
#[instrument(skip(token), fields(token_truncated = %format!("{}..", &token.chars().take(10).collect::<String>())))]
pub fn verify_token(token: &str) -> Result<String, JwtError> {
    let secret = get_jwt_secret();
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&secret),
        &Validation::default(),
    )?;
    
    Ok(token_data.claims.sub)
}

/// Generates a magic link URL for authentication
#[instrument(fields(email = %email, base_url = %base_url, expiry_minutes = %expiry_minutes))]
pub fn generate_magic_link(email: &str, base_url: &str, expiry_minutes: u64) -> String {
    let token = create_token(email, expiry_minutes);
    format!("{}/auth?token={}", base_url, token)
}

/// Gets the JWT secret from environment or uses default
#[instrument]
fn get_jwt_secret() -> Vec<u8> {
    std::env::var(JWT_SECRET_ENV)
        .map(|s| s.into_bytes())
        .unwrap_or_else(|_| DEFAULT_SECRET.to_vec())
}
