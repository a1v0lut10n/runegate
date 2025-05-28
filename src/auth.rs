// SPDX-License-Identifier: Apache-2.0
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, errors::Error as JwtError};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{instrument, warn, error};
use rand::Rng;

// Environment variable names
pub const JWT_SECRET_ENV: &str = "RUNEGATE_JWT_SECRET";
pub const RUNEGATE_ENV: &str = "RUNEGATE_ENV";
pub const MAGIC_LINK_EXPIRY_ENV: &str = "RUNEGATE_MAGIC_LINK_EXPIRY";

// Default values if not set in environment (only for development)
// const DEFAULT_SECRET: &[u8] = b"runegate_dev_only_secret_please_change_in_production"; // No longer used directly here
pub const DEFAULT_MAGIC_LINK_EXPIRY: u64 = 15; // Default expiry in minutes

#[derive(Debug)]
pub enum AuthError {
    TokenCreationError(String),
    TimeError(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::TokenCreationError(msg) => write!(f, "Token creation error: {}", msg),
            AuthError::TimeError(msg) => write!(f, "System time error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}


#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,   // The subject (usually email)
    pub exp: usize,    // Expiration time
    pub iat: usize,    // Issued at time
}

/// Creates a JWT token for a user
#[instrument(fields(email = %email, expiry_minutes = %expiry_minutes))]
pub fn create_token(email: &str, expiry_minutes: u64) -> Result<String, AuthError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AuthError::TimeError(format!("Failed to get current time: {}", e)))?
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
        .map_err(|e| AuthError::TokenCreationError(e.to_string()))
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
pub fn generate_magic_link(email: &str, base_url: &str, expiry_minutes: u64) -> Result<String, AuthError> {
    let token = create_token(email, expiry_minutes)?;
    Ok(format!("{}/auth?token={}", base_url, token))
}

/// Gets the JWT secret from environment or uses default
#[instrument]
pub fn get_jwt_secret() -> Vec<u8> {
    match std::env::var(JWT_SECRET_ENV) {
        Ok(secret_str) => {
            // Assuming the secret in env is a direct string representation
            // If it's hex or base64 encoded, decoding would be needed here.
            // For now, directly convert to bytes.
            let secret_bytes = secret_str.into_bytes();
            if secret_bytes.len() < 32 {
                error!("RUNEGATE_JWT_SECRET is set but is less than 32 bytes. This is insecure.");
                panic!("RUNEGATE_JWT_SECRET must be at least 32 bytes.");
            }
            secret_bytes
        }
        Err(_) => {
            match std::env::var(RUNEGATE_ENV).as_deref() {
                Ok("production") => {
                    error!("CRITICAL: RUNEGATE_JWT_SECRET is not set in a production environment!");
                    panic!("RUNEGATE_JWT_SECRET must be set in production.");
                }
                _ => {
                    warn!(
                        "RUNEGATE_JWT_SECRET is not set. Generating a temporary random secret. \
                        This is NOT suitable for production. Please set RUNEGATE_JWT_SECRET."
                    );
                    // Generate a 32-byte random secret
                    let mut rng = rand::thread_rng();
                    let secret: [u8; 32] = rng.gen();
                    secret.to_vec()
                }
            }
        }
    }
}

/// Gets the magic link expiry time in minutes from environment or uses default
#[instrument]
pub fn get_magic_link_expiry() -> u64 {
    std::env::var(MAGIC_LINK_EXPIRY_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAGIC_LINK_EXPIRY)
}
