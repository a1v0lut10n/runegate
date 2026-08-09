# Runegate Pluggable Auth UI Renderer Design

**Title:** Static, Phenotyper, and External Auth UI Rendering for Runegate  
**Project:** Runegate / Verbatime  
**Status:** Design note / change-request input  
**Scope:** Authentication UI rendering only: login, registration, magic-link status, MFA, invite, and error pages  
**Primary goal:** Preserve Runegate’s current static-page behavior while adding a configurable, branded, localized, server-rendered auth UI based on Phenotyper.

---

## 1. Summary

Runegate currently serves a static HTML page from an on-disk directory, commonly deployed to:

```text
/opt/runegate/static
```

This page supports the current lightweight magic-link flow: the user enters an email address and receives a magic link.

As Runegate evolves to support:

- login and registration modes,
- invite-only signup,
- Google authentication,
- MFA enrollment,
- WebAuthn/passkeys,
- TOTP,
- backup codes,
- localized market-specific auth pages,

the auth UI should become configurable and pluggable.

The proposed design introduces a **pluggable Auth UI renderer**:

```env
RUNEGATE_AUTH_UI_MODE=static|phenotyper|external
```

Recommended rollout:

```text
1. Preserve static mode exactly as today.
2. Add Phenotyper mode for branded, localized, server-rendered auth pages.
3. Keep external mode as an optional future escape hatch.
```

---

## 2. Design Goals

1. **Backward compatibility**  
   Existing deployments using `/opt/runegate/static` must keep working.

2. **Configurable branding**  
   Auth pages should be brandable per deployment and eventually per market/domain.

3. **Localization support**  
   Auth UI should support locales such as `de-CH`, `fr-CH`, `it-CH`, `nl-BE`, etc.

4. **Security-first rendering**  
   Auth pages should be rendered by Runegate on the same origin as the auth APIs whenever possible.

5. **Minimal frontend complexity**  
   Avoid making the Verbatime application own login forms, OAuth callbacks, MFA state, or auth cookies.

6. **Clear template contracts**  
   Each auth page should receive an explicit, documented context object.

7. **Incremental migration**  
   Static mode should remain the default until Phenotyper templates are proven.

---

## 3. Renderer Modes

### 3.1 Static Renderer

Current behavior.

```env
RUNEGATE_AUTH_UI_MODE=static
RUNEGATE_LOGIN_ASSETS_DIR=/opt/runegate/static
```

Runegate serves static files from disk.

Example:

```text
GET /auth/login
  → /opt/runegate/static/login.html
```

This mode is suitable for:

- existing deployments,
- very simple magic-link-only flows,
- minimal branded pages,
- fallback behavior if Phenotyper templates are missing.

Limitations:

- difficult to localize cleanly,
- less suitable for multi-step MFA flows,
- less suitable for per-market/domain customization,
- harder to pass structured state to pages safely.

---

### 3.2 Phenotyper Renderer

Recommended target mode.

```env
RUNEGATE_AUTH_UI_MODE=phenotyper
RUNEGATE_TEMPLATE_DIR=/opt/runegate/templates
RUNEGATE_BRAND_CONFIG=/etc/runegate/brand.toml
```

Runegate uses Phenotyper templates to render auth pages server-side.

Example:

```text
GET /auth/login?return_to=/app&locale=de-CH
  → render templates/login.html with structured context
```

This mode is suitable for:

- localized login/register pages,
- MFA enrollment and verification pages,
- invite-only flows,
- per-market copy and branding,
- server-side CSRF token injection,
- same-origin auth flows.

Benefits:

- auth UI remains owned by Runegate,
- browser stays same-origin,
- no CORS complexity,
- no external auth frontend required,
- template context is explicit and testable.

---

### 3.3 External Renderer

Optional future mode.

```env
RUNEGATE_AUTH_UI_MODE=external
RUNEGATE_EXTERNAL_LOGIN_URL=https://verbatime.ch/auth-ui/login
```

Runegate redirects to an external UI that calls Runegate auth APIs.

This mode is not recommended initially.

It introduces complexity around:

- CORS,
- CSRF,
- cookie scope,
- redirect-state handling,
- frontend/backend version compatibility,
- error handling across boundaries.

External mode may become useful later if a dedicated frontend team wants full control of auth UI deployment, but Phenotyper should be preferred for the initial gateway-mode architecture.

---

## 4. Configuration

### 4.1 Core UI Configuration

```env
RUNEGATE_AUTH_UI_MODE=static|phenotyper|external

# Static mode
RUNEGATE_LOGIN_ASSETS_DIR=/opt/runegate/static

# Phenotyper mode
RUNEGATE_TEMPLATE_DIR=/opt/runegate/templates
RUNEGATE_BRAND_CONFIG=/etc/runegate/brand.toml

# External mode
RUNEGATE_EXTERNAL_LOGIN_URL=https://example.com/auth-ui/login
RUNEGATE_EXTERNAL_REGISTER_URL=https://example.com/auth-ui/register
```

### 4.2 Auth Feature Configuration

The renderer should receive feature flags from Runegate configuration:

```env
RUNEGATE_AUTH_MAGIC_LINK_ENABLED=true
RUNEGATE_AUTH_GOOGLE_ENABLED=true
RUNEGATE_MFA_WEBAUTHN_ENABLED=true
RUNEGATE_MFA_TOTP_ENABLED=true
RUNEGATE_SIGNUP_POLICY=invite_only
```

### 4.3 Market-Aware Configuration

For multi-domain deployments, renderer context should be derived from market configuration.

Example:

```toml
[markets.ch]
domains = ["verbatime.ch", "www.verbatime.ch"]
default_locale = "de-CH"
locales = ["de-CH", "fr-CH", "it-CH"]
currency = "CHF"
signup_policy = "invite_only"

[markets.ch.branding]
product_name = "Verbatime"
market_name = "Switzerland"
logo_url = "/auth/assets/logo.svg"
primary_color = "#3366cc"

[markets.be]
domains = ["verbatime.be", "www.verbatime.be"]
default_locale = "nl-BE"
locales = ["nl-BE", "fr-BE", "de-BE"]
currency = "EUR"
signup_policy = "invite_only"

[markets.be.branding]
product_name = "Verbatime"
market_name = "Belgium"
logo_url = "/auth/assets/logo.svg"
primary_color = "#3366cc"
```

---

## 5. Template Directory Layout

Recommended Phenotyper template directory:

```text
/opt/runegate/templates/
  layout.html
  login.html
  register.html
  magic_link_sent.html
  magic_link_error.html
  invite_required.html
  invite_applied.html
  mfa_select.html
  mfa_webauthn_enroll.html
  mfa_webauthn_verify.html
  mfa_totp_enroll.html
  mfa_totp_verify.html
  backup_codes.html
  logout_confirm.html
  error.html
```

Recommended static assets directory:

```text
/opt/runegate/static/
  login.html
  css/
  js/
  img/
```

Recommended auth-specific assets path:

```text
/auth/assets/*
```

This allows Runegate to serve logos, CSS, and small JavaScript helpers for WebAuthn.

---

## 6. Route-to-Template Mapping

| Route | Template | Notes |
|---|---|---|
| `GET /auth/login` | `login.html` | Sign-in mode |
| `GET /auth/register` | `register.html` | Registration mode |
| `POST /auth/identify` success | `magic_link_sent.html` | Uniform response |
| `GET /auth/invite` valid | `invite_applied.html` | Invite cookie set |
| `GET /auth/invite` invalid | `invite_required.html` or `error.html` | Avoid leaking details |
| `GET /mfa` | `mfa_select.html` | If multiple MFA choices |
| `GET /mfa/webauthn/enroll` | `mfa_webauthn_enroll.html` | Passkey enrollment |
| `GET /mfa/webauthn/verify` | `mfa_webauthn_verify.html` | Returning-user challenge |
| `GET /mfa/totp/enroll` | `mfa_totp_enroll.html` | QR code setup |
| `GET /mfa/totp/verify` | `mfa_totp_verify.html` | TOTP challenge |
| `GET /mfa/backup-codes` | `backup_codes.html` | Show once |
| `GET /auth/error` | `error.html` | Generic auth error |

API routes such as `/auth/identify`, `/mfa/webauthn/attestation/options`, and `/mfa/totp/confirm` can return JSON or redirect to rendered templates depending on whether the page is progressively enhanced.

---

## 7. Common Template Context

Every rendered page should receive a common context.

Example:

```json
{
  "request": {
    "host": "verbatime.ch",
    "path": "/auth/login",
    "request_id": "req_123"
  },
  "market": {
    "id": "ch",
    "canonical_domain": "verbatime.ch",
    "market_name": "Switzerland",
    "currency": "CHF"
  },
  "locale": {
    "current": "de-CH",
    "available": ["de-CH", "fr-CH", "it-CH"],
    "default": "de-CH"
  },
  "branding": {
    "product_name": "Verbatime",
    "logo_url": "/auth/assets/logo.svg",
    "primary_color": "#3366cc",
    "support_email": "support@verbatime.ch"
  },
  "auth": {
    "mode": "login",
    "signup_policy": "invite_only",
    "magic_link_enabled": true,
    "google_enabled": true,
    "webauthn_enabled": true,
    "totp_enabled": true
  },
  "navigation": {
    "return_to": "/app",
    "login_url": "/auth/login?return_to=/app",
    "register_url": "/auth/register?return_to=/app"
  },
  "security": {
    "csrf_token": "csrf_...",
    "csp_nonce": "nonce_..."
  },
  "messages": {
    "title": "Sign in to Verbatime",
    "subtitle": "Swiss German to High German subtitles, tailored for Switzerland.",
    "flash": null,
    "error": null
  }
}
```

This common context should be extended by page-specific context.

---

## 8. Page-Specific Contexts

### 8.1 Login Page

```json
{
  "auth": {
    "mode": "login"
  },
  "form": {
    "email": "",
    "show_invite_code": false
  },
  "messages": {
    "title": "Sign in to Verbatime",
    "submit_label": "Email me a sign-in link",
    "alternate_action": {
      "label": "Create an account",
      "url": "/auth/register?return_to=/app"
    }
  }
}
```

### 8.2 Registration Page

```json
{
  "auth": {
    "mode": "register"
  },
  "form": {
    "email": "",
    "show_invite_code": true
  },
  "messages": {
    "title": "Create your Verbatime account",
    "submit_label": "Continue",
    "alternate_action": {
      "label": "Already have an account? Sign in",
      "url": "/auth/login?return_to=/app"
    }
  }
}
```

### 8.3 Magic Link Sent

```json
{
  "messages": {
    "title": "Check your email",
    "body": "If this email is eligible, we sent a sign-in link.",
    "security_note": "The link expires soon and can only be used once."
  }
}
```

Important: wording should avoid user enumeration.

### 8.4 Invite Required

```json
{
  "messages": {
    "title": "Invite required",
    "body": "You need an invite to create a Verbatime account in this market.",
    "support_hint": "Ask the person who invited you or contact support."
  }
}
```

### 8.5 MFA Selection

```json
{
  "mfa": {
    "required": true,
    "first_login": true,
    "methods": [
      {
        "id": "webauthn",
        "label": "Use a passkey",
        "recommended": true
      },
      {
        "id": "totp",
        "label": "Use an authenticator app",
        "recommended": false
      }
    ]
  },
  "messages": {
    "title": "Secure your account",
    "subtitle": "Set up a second factor before continuing."
  }
}
```

### 8.6 WebAuthn Enrollment

```json
{
  "mfa": {
    "method": "webauthn",
    "mode": "enroll",
    "options_endpoint": "/mfa/webauthn/attestation/options",
    "finish_endpoint": "/mfa/webauthn/attestation/finish"
  },
  "messages": {
    "title": "Create a passkey",
    "body": "Use your device passcode, fingerprint, face recognition, or security key."
  }
}
```

### 8.7 TOTP Enrollment

```json
{
  "mfa": {
    "method": "totp",
    "mode": "enroll",
    "qr_svg": "<svg>...</svg>",
    "manual_secret": "ABCD EFGH IJKL MNOP",
    "confirm_endpoint": "/mfa/totp/confirm"
  },
  "messages": {
    "title": "Set up an authenticator app",
    "body": "Scan the QR code, then enter the generated code."
  }
}
```

---

## 9. Localization Strategy

Phenotyper templates should not hard-code all strings.

Recommended model:

```text
Template = layout and structure
Message bundle = localized text
Context = dynamic values
```

Possible message bundle layout:

```text
/opt/runegate/i18n/
  de-CH.toml
  fr-CH.toml
  it-CH.toml
  nl-BE.toml
  de-BE.toml
  en.toml
```

Example:

```toml
[login]
title = "Bei Verbatime anmelden"
submit_label = "Anmeldelink per E-Mail senden"
register_link = "Konto erstellen"

[magic_link_sent]
title = "Prüfen Sie Ihre E-Mail"
body = "Falls diese E-Mail-Adresse berechtigt ist, haben wir einen Anmeldelink gesendet."
```

Locale resolution should be performed before rendering:

```text
1. URL locale
2. locale cookie
3. Accept-Language
4. GeoIP hint
5. market default locale
```

The resolved locale should be included in the template context.

---

## 10. Security Requirements

### 10.1 Escaping

Phenotyper must escape untrusted values by default.

Untrusted values include:

- email input,
- return_to,
- error messages from query strings,
- invite codes,
- user-agent-derived data.

Only explicitly safe HTML should be rendered raw, such as server-generated QR SVG if treated carefully.

### 10.2 CSRF

All forms should include CSRF tokens.

Example:

```html
<input type="hidden" name="csrf" value="{{ security.csrf_token }}">
```

CSRF tokens should be validated on:

- `/auth/identify`,
- `/auth/logout`,
- `/mfa/totp/confirm`,
- backup code regeneration,
- any state-changing POST.

### 10.3 CSP

Runegate should set a strict Content Security Policy.

Example:

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{{ security.csp_nonce }}';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  connect-src 'self';
  frame-ancestors 'none';
```

If external assets are allowed, they must be explicitly configured.

### 10.4 No User Enumeration

Templates must support uniform messages.

Example:

```text
"If this email is eligible, we sent a sign-in link."
```

Do not render:

```text
"No account exists for this email."
```

unless explicitly allowed for a trusted admin flow.

### 10.5 Same-Origin Preference

Static and Phenotyper modes should keep auth pages same-origin with auth APIs:

```text
/auth/login
/auth/identify
/mfa/...
```

This avoids most CORS and cookie problems.

---

## 11. WebAuthn JavaScript Helpers

WebAuthn requires small client-side JavaScript.

This can be served from:

```text
/auth/assets/webauthn.js
```

The helper should:

- fetch attestation/assertion options,
- call `navigator.credentials.create()` or `navigator.credentials.get()`,
- POST the result back to Runegate,
- handle browser errors gracefully.

The template context should provide endpoint URLs, not hard-code them.

Example:

```json
{
  "mfa": {
    "options_endpoint": "/mfa/webauthn/attestation/options",
    "finish_endpoint": "/mfa/webauthn/attestation/finish"
  }
}
```

---

## 12. TOTP Rendering

For TOTP enrollment, Runegate can generate:

- an `otpauth://` URI,
- a QR code SVG or PNG,
- a manual fallback secret.

The QR code can be embedded directly in the template context.

Security note:

- Store TOTP secret encrypted at rest.
- Show the secret only during enrollment.
- Confirm with a code before persisting the factor as active.

---

## 13. Error Handling

Use a generic error template:

```text
error.html
```

Context:

```json
{
  "error": {
    "code": "magic_link_expired",
    "title": "This link has expired",
    "message": "Please request a new sign-in link.",
    "recover_url": "/auth/login"
  }
}
```

Error codes should be stable and documented.

Recommended error codes:

```text
magic_link_expired
magic_link_used
magic_link_invalid
invite_required
invite_invalid_or_expired
mfa_required
mfa_failed
oauth_state_invalid
oauth_callback_failed
session_expired
csrf_invalid
return_to_invalid
```

Avoid showing sensitive internal details.

---

## 14. Static-to-Phenotyper Migration

### Phase 1 — Preserve Static

Default:

```env
RUNEGATE_AUTH_UI_MODE=static
RUNEGATE_LOGIN_ASSETS_DIR=/opt/runegate/static
```

No behavior change.

### Phase 2 — Add Renderer Abstraction

Introduce an internal trait/interface:

```text
AuthUiRenderer
  render_login(context)
  render_register(context)
  render_magic_link_sent(context)
  render_mfa_select(context)
  render_error(context)
```

Static renderer can return static files or minimal transformed content.

### Phase 3 — Add Phenotyper Renderer

Implement:

```text
PhenotyperAuthUiRenderer
```

using:

```env
RUNEGATE_TEMPLATE_DIR=/opt/runegate/templates
```

### Phase 4 — Add Sample Templates

Ship default templates as examples, possibly under:

```text
examples/templates/
```

or package them as deployable assets.

### Phase 5 — Enable Per Deployment

Switch staging:

```env
RUNEGATE_AUTH_UI_MODE=phenotyper
```

Then production.

---

## 15. Internal Renderer Interface

A conceptual Rust trait could look like:

```rust
pub trait AuthUiRenderer: Send + Sync {
    fn render_login(&self, ctx: &AuthUiContext) -> Result<HttpResponse>;
    fn render_register(&self, ctx: &AuthUiContext) -> Result<HttpResponse>;
    fn render_magic_link_sent(&self, ctx: &AuthUiContext) -> Result<HttpResponse>;
    fn render_invite_required(&self, ctx: &AuthUiContext) -> Result<HttpResponse>;
    fn render_mfa_select(&self, ctx: &AuthUiContext) -> Result<HttpResponse>;
    fn render_error(&self, ctx: &AuthUiContext) -> Result<HttpResponse>;
}
```

Where:

```rust
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
```

The exact Rust types can evolve, but the separation should remain clear.

---

## 16. Progressive Enhancement

Auth pages should work with minimal JavaScript where possible.

JavaScript is required for:

- WebAuthn/passkeys,
- richer UI validation,
- optional dynamic session checks.

Magic-link login and TOTP confirmation can work with normal HTML forms.

This improves reliability and avoids over-coupling auth to a large frontend bundle.

---

## 17. Deployment Layout

Suggested deployment layout:

```text
/opt/runegate/
  bin/runegate
  static/
    login.html
    css/
    js/
    img/
  templates/
    layout.html
    login.html
    register.html
    mfa_select.html
    ...
  i18n/
    de-CH.toml
    fr-CH.toml
    it-CH.toml
    nl-BE.toml
  config/
    runegate.toml
    brand.toml
```

This keeps templates and translations outside the binary while preserving the ability to package defaults.

---

## 18. Interaction with Verbatime

The Verbatime app should not own the auth UI when Runegate is in gateway mode.

Verbatime should:

- link to `/auth/login`,
- link to `/auth/register`,
- optionally call `/auth/session`,
- render public and protected product pages,
- trust identity headers injected by Runegate.

Runegate should:

- render auth pages,
- process auth forms,
- set PREAUTH and SESSION cookies,
- redirect back to Verbatime after successful auth.

This preserves the separation:

```text
Verbatime owns product UI.
Runegate owns auth UI.
```

---

## 19. Development Tasks

### Sprint 0 — Preserve Current Static Mode

- [ ] Add `RUNEGATE_AUTH_UI_MODE=static` with current behavior.
- [ ] Ensure `/opt/runegate/static` remains supported.
- [ ] Add compatibility tests for the current magic-link page.

### Sprint 1 — Renderer Abstraction

- [ ] Introduce `AuthUiRenderer` abstraction.
- [ ] Add common `AuthUiContext`.
- [ ] Route `/auth/login`, `/auth/register`, `/mfa/*`, and error pages through the renderer.

### Sprint 2 — Template Context

- [ ] Define request, market, locale, branding, auth, navigation, security, and message context structs.
- [ ] Add CSRF token and CSP nonce generation.
- [ ] Add return_to validation before context construction.

### Sprint 3 — Phenotyper Renderer

- [ ] Implement `PhenotyperAuthUiRenderer`.
- [ ] Add `RUNEGATE_TEMPLATE_DIR`.
- [ ] Load templates from disk.
- [ ] Add template rendering errors with safe fallback to `error.html`.

### Sprint 4 — Localization

- [ ] Add i18n message loading.
- [ ] Add locale resolution.
- [ ] Validate locale against market config.
- [ ] Provide localized message bundles to templates.

### Sprint 5 — MFA Templates

- [ ] Add WebAuthn enrollment and verification pages.
- [ ] Add TOTP enrollment and verification pages.
- [ ] Add backup code display template.
- [ ] Add `/auth/assets/webauthn.js`.

### Sprint 6 — Invite and Registration Templates

- [ ] Add invite required/applied templates.
- [ ] Add registration mode template.
- [ ] Add no-enumeration magic-link-sent copy.

### Sprint 7 — Security Hardening

- [ ] Enforce auto-escaping.
- [ ] Add CSP headers.
- [ ] Add CSRF to all form templates.
- [ ] Ensure errors do not leak sensitive details.
- [ ] Strip untrusted fields from template context.

### Sprint 8 — Documentation

- [ ] Document renderer modes.
- [ ] Document template context schema.
- [ ] Provide sample templates and i18n files.
- [ ] Provide migration guide from static to Phenotyper.

---

## 20. Acceptance Criteria

- Existing static login page behavior remains supported.
- `RUNEGATE_AUTH_UI_MODE=static` behaves as current deployments expect.
- `RUNEGATE_AUTH_UI_MODE=phenotyper` renders login, register, MFA, invite, and error pages from templates.
- Template context includes market, locale, branding, auth method availability, CSRF token, CSP nonce, and validated return_to.
- Auth pages are localized according to the resolved locale.
- Forms include CSRF tokens.
- CSP is emitted for rendered pages.
- User enumeration is avoided in login/register feedback.
- WebAuthn helper JavaScript is served same-origin.
- Missing or broken templates fail safely with a generic error page or static fallback.

---

## 21. Recommended Initial Implementation

Start with:

```env
RUNEGATE_AUTH_UI_MODE=static
```

Then implement the renderer abstraction and add Phenotyper mode behind configuration.

Recommended target for Verbatime:

```env
RUNEGATE_AUTH_UI_MODE=phenotyper
RUNEGATE_TEMPLATE_DIR=/opt/runegate/templates
RUNEGATE_BRAND_CONFIG=/etc/runegate/brand.toml
```

Keep external mode as a documented future option, not part of the initial implementation.

---

## 22. Bottom Line

The pluggable auth UI renderer lets Runegate evolve from a single static magic-link page into a branded, localized, MFA-capable authentication experience without handing auth UI ownership to the Verbatime application.

The recommended design is:

```text
Static mode for backward compatibility.
Phenotyper mode for production-grade branded auth UI.
External mode only as a future escape hatch.
```

This keeps Runegate responsible for identity, keeps Verbatime responsible for product UI, and supports the multi-market Verbatime deployment model cleanly.
