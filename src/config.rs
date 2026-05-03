use crate::email::EmailConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub base_url: String,
    pub email_config: EmailConfig,
}
