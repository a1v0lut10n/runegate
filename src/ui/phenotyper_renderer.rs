use super::{AuthUiContext, AuthUiRenderer, RendererError};
use actix_web::HttpResponse;
use std::path::PathBuf;

pub struct PhenotyperRenderer {
    _template_dir: PathBuf,
}

impl PhenotyperRenderer {
    pub fn new(template_dir: PathBuf) -> Self {
        Self {
            _template_dir: template_dir,
        }
    }
}

impl AuthUiRenderer for PhenotyperRenderer {
    fn render_login(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        // Placeholder until phenotyper templates are compiled
        Err(RendererError::TemplateNotFound("login.html".to_string()))
    }

    fn render_register(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        Err(RendererError::TemplateNotFound("register.html".to_string()))
    }

    fn render_magic_link_sent(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        Err(RendererError::TemplateNotFound(
            "magic_link_sent.html".to_string(),
        ))
    }

    fn render_invite_required(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        Err(RendererError::TemplateNotFound(
            "invite_required.html".to_string(),
        ))
    }

    fn render_mfa_select(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        Err(RendererError::TemplateNotFound(
            "mfa_select.html".to_string(),
        ))
    }

    fn render_error(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        Err(RendererError::TemplateNotFound("error.html".to_string()))
    }
}
