# RUN-0004 — Magic-link-only backward compatibility for the gateway branch

**Status:** Done (pending merge of `feature/RUN-4-gateway-functionality`)
**Date:** 2026-08-09
**Branch:** `feature/RUN-4-gateway-functionality`

## Premise

The gateway branch (OIDC, MFA, Postgres identity, upload tickets, pluggable
auth UI) is confirmed working for verbatime, but the repo's own acceptance
criterion — *"Running with `RUNEGATE_MODE=magic-link-only` behaves exactly as
today"* (`docs/runegate-change-request.md`) — was unmet, and nothing tested it.
An audit against `main` (= published v0.3.1) found:

- **R1 (critical):** `/login.html` was rendered from a default assets dir of
  `/opt/runegate/static`; a legacy deployment serving from CWD-relative
  `static/` got HTTP 500 on its login page.
- **R2 (critical, security):** `/`, `/favicon.*`, `/_app/*` became public
  *proxied* paths in every mode — on v0.3.x they required login. An app whose
  UI lives at `/` would be exposed unauthenticated.
- **R4:** a new middleware branch redirects PREAUTH sessions to `/mfa`, which
  cannot render in magic-link-only mode (no `mfa_select.html`).
- **R5:** `RUNEGATE_MODE` was parsed but gated nothing.
- Legacy JWTs (no `jti` claim) were rejected after upgrade, killing in-flight
  magic links.
- Already-authenticated users hitting `/login.html` were redirected to a
  hardcoded `/app` (verbatime's path) instead of the deployment's target.
- `/admin/invites` 500ed ("app data not configured") without `DATABASE_URL`.
- No in-process tests could exist: the whole actix `App` was built inline in
  `main.rs` (R8).

## Action items

- **A0 — App factory extraction.** New `src/app.rs`: `AppSettings`,
  `configure_routes()` (the full route table, single source of truth),
  `build_renderer()`, and all UI/proxy/debug handlers moved out of `main.rs`.
  `main.rs` keeps env parsing, store construction, and `HttpServer` setup.
- **A1 — Mode gating (fixes R2/R4/R5).** `RunegateMode`/`AuthUiMode` moved to
  `config.rs` with `from_env()`. `AuthMiddleware::with_mode(...)`: the public
  paths `/`, `/favicon.*`, `/_app*`, `/mfa*`, `/keys*` and the PREAUTH→`/mfa`
  branch now exist **only** in gateway mode; `auth_check_and_proxy` applies the
  same gate. Magic-link-only mode reproduces the v0.3.x behaviour (everything
  gated, redirect to `/login.html`). Verbatime runs `RUNEGATE_MODE=gateway`
  and is unaffected.
- **A2 — Login assets resolution (fixes R1).** Default assets dir is now: env
  `RUNEGATE_LOGIN_ASSETS_DIR` → CWD-relative `static/` when it contains
  `login.html` (v0.3.x behaviour) → `/opt/runegate/static` (deployed layout;
  also what verbatime resolves to via its `WorkingDirectory=/opt/runegate`).
  Missing `register.html` now falls back to the login page instead of 500.
- **A3 — Legacy token acceptance.** `Claims.jti` is `#[serde(default)]`;
  v0.3.x tokens (no `jti`) verify again. Replay tracking (still a TODO in
  `magic_consume`) treats them as untracked.
- **A4 — Redirect unification.** `config::default_redirect()`
  (`RUNEGATE_DEFAULT_REDIRECT`, default `/proxy/`) used by magic-consume, MFA,
  OIDC, and the already-authenticated login/register bounce (previously
  hardcoded `/app`).
- **A5 — Degraded-config robustness.** Admin handlers take
  `Option<web::Data<PgStore>>` (503 with a clear message instead of a 500
  extraction error when the route is reached without a database).
- **A6 — Backward-compat test suites.** `tests/common/mod.rs` builds the real
  app in-process (in-memory sessions, SMTP pointed at a closed port, echo
  upstream via `actix-test`). `tests/magic_link_backward_compat_tests.rs`
  (14 tests) pins the legacy contract: login page from repo `static/`, root
  and arbitrary paths 302 → `/login.html` (never `/mfa`), full magic-link
  roundtrip with cookie-attribute checks (`HttpOnly`, `SameSite=Lax`,
  host-only, no `Secure` in dev), v0.3.x token acceptance, identity-header
  injection + spoof-stripping + `/proxy/*` prefix mapping, redirect default
  and override, and clean degradation of OIDC/admin/upload endpoints.
  `tests/gateway_mode_tests.rs` (3 tests) pins the verbatime-facing side:
  public proxied root/assets with `X-Runegate-Authenticated: false`, gated
  app paths, unchanged roundtrip.
- **A7 — Hygiene.** `cargo fmt` across the branch, clippy `-D warnings`
  clean (a pre-existing `useless_format` error would have failed CI), new
  gateway-mode variable block in `.env.example`.

## Verification

- [x] `cargo test` — 20 passing (14 + 3 new in-process, 3 existing rate-limit
      unit tests); ignored suites unchanged.
- [x] `cargo clippy --workspace --all-targets` — no warnings.
- [x] `cargo fmt --check` — clean.
- [x] Gateway-mode tests confirm verbatime-visible behaviour is preserved.

## Known deviations from v0.3.x, accepted deliberately (pinned in tests)

1. **SMTP failure returns 200** and logs the magic link (commit `66f116a`);
   v0.3.x returned 500. Convenient in dev, but in production it masks mail
   outages and writes a live login link into the logs. Recommend gating the
   fallback on `RUNEGATE_ENV != production` in a follow-up.
2. Two additive proxy headers, `X-User-Id` / `X-User-Email` — and `X-User-Id`
   carries the **email**. Documented in `docs/howto/fronting-a-service.md`.
3. New endpoints exist in magic-link-only mode but degrade cleanly
   (OIDC 500 "not configured", upload 501, admin gated behind the auth
   redirect).

## Out of scope / follow-ups

- `jti` single-use enforcement is still a TODO in `magic_consume` (README
  overstates this as implemented).
- `infra/tests/run_e2e_tests.sh` asserts pre-refactor behaviour (`/auth/login`
  redirect, form-encoded `/auth/identify`) and needs updating.
- `create_auth_ui_context` still hardcodes verbatime branding (inert today —
  the static renderer ignores it, phenotyper mode is unimplemented).
- Consider 503 instead of 500 for unconfigured `/auth/google/*`.
