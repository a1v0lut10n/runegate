// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub from_address: String,
    pub subject: String,
    pub body_template: String,
}
