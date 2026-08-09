pub mod context;
pub mod phenotyper_renderer;
pub mod static_renderer;

use actix_web::HttpResponse;
use context::AuthUiContext;
use std::fmt;

#[derive(Debug)]
pub enum RendererError {
    TemplateNotFound(String),
    RenderFailed(String),
}

impl std::error::Error for RendererError {}

impl fmt::Display for RendererError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TemplateNotFound(s) => write!(f, "Template not found: {}", s),
            Self::RenderFailed(s) => write!(f, "Render failed: {}", s),
        }
    }
}

pub trait AuthUiRenderer: Send + Sync {
    fn render_login(&self, ctx: &AuthUiContext) -> Result<HttpResponse, RendererError>;
    fn render_register(&self, ctx: &AuthUiContext) -> Result<HttpResponse, RendererError>;
    fn render_magic_link_sent(&self, ctx: &AuthUiContext) -> Result<HttpResponse, RendererError>;
    fn render_invite_required(&self, ctx: &AuthUiContext) -> Result<HttpResponse, RendererError>;
    fn render_mfa_select(&self, ctx: &AuthUiContext) -> Result<HttpResponse, RendererError>;
    fn render_error(&self, ctx: &AuthUiContext) -> Result<HttpResponse, RendererError>;
}
