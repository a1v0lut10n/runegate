# Runegate Gateway Implementation Plan

This plan consolidates the migration strategy to evolve Runegate from a single-instance magic-link service into a robust identity and edge authorization gateway. It incorporates the architectural shift to use Redis for hot, short-lived auth state and PostgreSQL for durable identity and policy state, while adding Google OIDC, MFA, upload tickets, invite-only signup, and a Pluggable Auth UI Renderer.

## User Review Required

> [!WARNING]
> **State Store Migration**: We will be replacing the current memory-based session and rate-limit storage with explicit Storage Traits. Once Redis and Postgres are introduced, existing deployments without these dependencies will need to run in `magic-link-only` mode with memory stores, or migrate to the new infrastructure.

> [!IMPORTANT]
> **Auth UI Renderer Migration**: `RUNEGATE_AUTH_UI_MODE` will default to `static` for backward compatibility. New deployments should transition to `phenotyper` mode to utilize server-rendered, branded, and localized templates.

## Proposed Changes

---

### Core Storage Abstractions & Mode Splitting (Completed)

Introduce explicit storage traits and the `RUNEGATE_MODE` flag. Establish memory-backed stores as the baseline to support `magic-link-only` mode without requiring external databases.

#### [MODIFY] [src/main.rs](file:///aivolution/projects/runegate/src/main.rs)
- Introduce `RUNEGATE_MODE` configuration parsing.

#### [NEW] [src/store.rs](file:///aivolution/projects/runegate/src/store/mod.rs)
- Define async traits: `SessionStore`, `PreauthStore`, `LinkStateStore`, `RateLimitStore`, `ChallengeStore`.
- Implement `Memory*` fallback implementations for backward compatibility.

---

### Pluggable Auth UI Renderer Integration

Introduce the `AuthUiRenderer` abstraction to support static, Phenotyper, and external UI rendering modes. This ensures Runegate retains ownership of the auth UI (same-origin) while allowing per-market branding and localization.

#### [MODIFY] [src/main.rs](file:///aivolution/projects/runegate/src/main.rs)
- Parse `RUNEGATE_AUTH_UI_MODE` (`static` | `phenotyper` | `external`).
- Initialize the selected renderer and pass it to route handlers.

#### [NEW] [src/ui/mod.rs](file:///aivolution/projects/runegate/src/ui/mod.rs)
- Define `AuthUiRenderer` async trait (`render_login`, `render_register`, `render_mfa_select`, etc.).
- Define common `AuthUiContext` struct encapsulating `request`, `market`, `locale`, `branding`, `auth`, `navigation`, `security`, and `messages`.

#### [NEW] [src/ui/static_renderer.rs](file:///aivolution/projects/runegate/src/ui/static_renderer.rs)
- Implement `AuthUiRenderer` by serving files from `/opt/runegate/static` for backward compatibility.

#### [NEW] [src/ui/phenotyper_renderer.rs](file:///aivolution/projects/runegate/src/ui/phenotyper_renderer.rs)
- Implement `AuthUiRenderer` using compiled Phenotyper DSL templates.
- Support localized message bundles and context-aware rendering.

---

### Redis Integration (Ephemeral Auth State)

Migrate hot, high-churn authentication state to Redis for multi-instance compatibility.

#### [MODIFY] [Cargo.toml](file:///aivolution/projects/runegate/Cargo.toml)
- Add Redis client dependency (`redis` crate, v1.2.0 eq).

#### [NEW] [src/store/redis.rs](file:///aivolution/projects/runegate/src/store/redis.rs)
- Implement all Phase 1 traits using Redis.
- Add support for OAuth nonces, PKCE, WebAuthn/TOTP challenge state, and invite-flow temporary state.

---

### Magic-Link Hardening & Session Progression

Refactor the existing magic-link flow to align with the new identifier-first, pre-auth paradigm.

#### [MODIFY] [src/auth.rs](file:///aivolution/projects/runegate/src/auth.rs)
- Adapt magic-link generation to embed single-use `jti`.
- Bind links to device cookies.

#### [NEW] [src/routes/auth.rs](file:///aivolution/projects/runegate/src/routes/auth.rs)
- `POST /auth/identify`: Uniform response handling.
- `POST /auth/magic/start`: Issue link.
- `GET /auth/magic/consume`: Verify link and issue `PREAUTH` cookie.

#### [MODIFY] [src/middleware.rs](file:///aivolution/projects/runegate/src/middleware.rs)
- Differentiate between `PREAUTH` and `SESSION` levels.
- Redirect `PREAUTH` users to `/mfa` before granting full session access to upstream targets.

---

### Google OIDC & MFA Implementation

Introduce Google SSO and mandatory MFA (WebAuthn / TOTP) in gateway mode.

#### [NEW] [src/routes/oidc.rs](file:///aivolution/projects/runegate/src/routes/oidc.rs)
- `GET /auth/google/start` and `GET /auth/google/callback` endpoints.
- PKCE generation and validation backed by Redis.

#### [NEW] [src/routes/mfa.rs](file:///aivolution/projects/runegate/src/routes/mfa.rs)
- WebAuthn endpoints (`/mfa/webauthn/*`).
- TOTP endpoints (`/mfa/totp/*`).
- Support for generating and verifying backup codes.

---

### Edge Authorization: Upload Tickets

Provide short-lived upload tickets (JWTs) for downstream services like `tusd`.

#### [NEW] [src/routes/upload.rs](file:///aivolution/projects/runegate/src/routes/upload.rs)
- `POST /upload-ticket`: Endpoint for Runegate-minted tickets.
- Expose JWKS at `/keys/upload_jwks.json`.

---

### Durable Identity & Invite-Only Onboarding (PostgreSQL)

Introduce PostgreSQL as the system of record for identities, credentials, invites, and audits.

#### [MODIFY] [Cargo.toml](file:///aivolution/projects/runegate/Cargo.toml)
- Add PostgreSQL dependencies (`sqlx` v0.8.6).

#### [NEW] [migrations/](file:///aivolution/projects/runegate/migrations/)
- SQL schemas for `users`, `oauth_identities`, `mfa_enrollments`, `backup_codes`, `invites`, `invite_usages`.

#### [NEW] [src/store/pg.rs](file:///aivolution/projects/runegate/src/store/pg.rs)
- Implement `IdentityStore`, `InviteStore`, and `AuditStore`.

#### [NEW] [src/routes/admin.rs](file:///aivolution/projects/runegate/src/routes/admin.rs)
- `POST /admin/invites`, `GET /admin/invites`, `POST /admin/invites/{id}/revoke`.
- Protected by `RUNEGATE_ADMIN_API_TOKEN`.

#### [MODIFY] [src/routes/auth.rs](file:///aivolution/projects/runegate/src/routes/auth.rs)
- Update `identify` and OIDC callback flows to respect `RUNEGATE_SIGNUP_POLICY=invite_only`.
- Consume invites atomically using the `InviteStore`.

## Verification Plan

### Automated Tests
- Unit tests for all storage trait implementations (`Memory`, `Redis`, `Postgres`).
- Integration tests simulating the `magic-link-only` backward-compatible flow.
- Integration tests simulating the full `gateway` flow: Identify -> Magic Link / OIDC -> PREAUTH -> MFA -> SESSION.
- Integration tests verifying atomic invite consumption and correct policy enforcement (open vs. invite-only).
- UI renderer tests validating fallback to static mode and proper context injection for Phenotyper.

### Manual Verification
- Deploy locally with Redis and Postgres containers.
- Register via Google OIDC and complete WebAuthn enrollment using the Phenotyper-rendered UI.
- Verify CSRF and CSP injection in rendered templates.
- Ensure the upstream target service only receives requests with injected `X-User-*` headers once a full `SESSION` is established.
