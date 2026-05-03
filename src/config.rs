use crate::email::EmailConfig;
use serde::{Deserialize, Serialize};

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
}
