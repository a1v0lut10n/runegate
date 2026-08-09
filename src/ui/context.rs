use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUiContext {
    pub request: RequestContext,
    pub market: MarketContext,
    pub locale: LocaleContext,
    pub branding: BrandingContext,
    pub auth: AuthContext,
    pub navigation: NavigationContext,
    pub security: SecurityContext,
    pub messages: MessageContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub host: String,
    pub path: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketContext {
    pub id: String,
    pub canonical_domain: String,
    pub market_name: String,
    pub currency: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocaleContext {
    pub current: String,
    pub available: Vec<String>,
    pub default: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandingContext {
    pub product_name: String,
    pub logo_url: String,
    pub primary_color: String,
    pub support_email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub mode: String,
    pub signup_policy: String,
    pub magic_link_enabled: bool,
    pub google_enabled: bool,
    pub webauthn_enabled: bool,
    pub totp_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NavigationContext {
    pub return_to: String,
    pub login_url: String,
    pub register_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    pub csrf_token: String,
    pub csp_nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageContext {
    pub title: String,
    pub subtitle: Option<String>,
    pub flash: Option<String>,
    pub error: Option<String>,
}
