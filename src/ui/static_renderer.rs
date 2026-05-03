use super::{AuthUiContext, AuthUiRenderer, RendererError};
use actix_web::HttpResponse;
use std::path::PathBuf;

pub struct StaticRenderer {
    assets_dir: PathBuf,
}

impl StaticRenderer {
    pub fn new(assets_dir: PathBuf) -> Self {
        Self { assets_dir }
    }

    fn serve_static(&self, filename: &str) -> Result<HttpResponse, RendererError> {
        let path = self.assets_dir.join(filename);
        match std::fs::read_to_string(&path) {
            Ok(content) => Ok(HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(content)),
            Err(_) => Err(RendererError::TemplateNotFound(filename.to_string())),
        }
    }
}

impl AuthUiRenderer for StaticRenderer {
    fn render_login(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        self.serve_static("login.html")
    }

    fn render_register(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        self.serve_static("register.html")
    }

    fn render_magic_link_sent(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        // Fallback to login.html or some static message if not exists
        self.serve_static("magic_link_sent.html")
            .or_else(|_| self.serve_static("login.html"))
    }

    fn render_invite_required(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        self.serve_static("invite_required.html")
            .or_else(|_| self.serve_static("login.html"))
    }

    fn render_mfa_select(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        self.serve_static("mfa_select.html")
    }

    fn render_error(&self, _ctx: &AuthUiContext) -> Result<HttpResponse, RendererError> {
        self.serve_static("error.html")
            .or_else(|_| Ok(HttpResponse::InternalServerError().body("An error occurred.")))
    }
}
