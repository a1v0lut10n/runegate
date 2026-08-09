use crate::email::EmailConfig;
use serde::{Deserialize, Serialize};

pub const RUNEGATE_MODE_ENV: &str = "RUNEGATE_MODE";
pub const RUNEGATE_AUTH_UI_MODE_ENV: &str = "RUNEGATE_AUTH_UI_MODE";
pub const RUNEGATE_DEFAULT_REDIRECT_ENV: &str = "RUNEGATE_DEFAULT_REDIRECT";

/// Operating mode. `MagicLinkOnly` (the default) must behave identically to
/// the published magic-link-only release: gateway-mode conveniences such as
/// public root/asset paths are only enabled under `Gateway`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunegateMode {
    #[default]
    MagicLinkOnly,
    Gateway,
}

impl RunegateMode {
    pub fn from_env() -> Self {
        match std::env::var(RUNEGATE_MODE_ENV).as_deref() {
            Ok("gateway") => RunegateMode::Gateway,
            _ => RunegateMode::MagicLinkOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthUiMode {
    #[default]
    Static,
    Phenotyper,
    External,
}

impl AuthUiMode {
    pub fn from_env() -> Self {
        match std::env::var(RUNEGATE_AUTH_UI_MODE_ENV).as_deref() {
            Ok("phenotyper") => AuthUiMode::Phenotyper,
            Ok("external") => AuthUiMode::External,
            _ => AuthUiMode::Static,
        }
    }
}

/// Post-login redirect target: `RUNEGATE_DEFAULT_REDIRECT`, or the historical
/// `/proxy/` default that the published release hardcoded.
pub fn default_redirect() -> String {
    std::env::var(RUNEGATE_DEFAULT_REDIRECT_ENV).unwrap_or_else(|_| "/proxy/".to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub base_url: String,
    pub email_config: EmailConfig,
    pub google_oidc: Option<OidcConfig>,
    pub upload_private_key: Option<String>,
    pub upload_jwks: Option<String>,
}
