# Magic-Link-Only Backward Compatibility Hardened, Tested, and Verified on aibox

**Date**: 2026-08-09
**Time**: 03:46:58
**Status**: Completed

## Summary

Audited `feature/RUN-4-gateway-functionality` against the published v0.3.1
release and found the magic-link-only contract broken in several ways, despite
the branch's own acceptance criterion that magic-link-only behaviour "remains
identical". Fixed the regressions by making `RUNEGATE_MODE` a real gate,
extracted an app factory to make the routing table testable in-process, pinned
both operational modes with 17 integration tests, and verified zero regression
on the deployed verbatime + runegate instance on aibox — including live logins
by a registered Google account.

## Context

Runegate is being reused to front a second service (aicognito) while verbatime
runs the gateway branch in production on aibox with registered users. Before
extending further, the magic-link-only mode shipped to crates.io users (2000+
downloads) needed assurance that the OAuth/OIDC work had not broken it. It
had — silently, because the actix `App` was built inline in `main.rs` and no
in-process test could exercise the real route table.

## Details

Regressions found (vs v0.3.1) and fixed:

- **Login page 500**: the new `StaticRenderer` defaulted its assets dir to
  `/opt/runegate/static`; legacy deployments serve from CWD-relative
  `static/`. Resolution order is now env var → CWD `static/` → deployed path.
- **Public root leak (security)**: `/`, `/favicon.*`, `/_app/*` were publicly
  proxied in every mode. Now gateway-mode-only; magic-link-only keeps
  everything behind auth, and the PREAUTH → `/mfa` middleware branch (a
  latent redirect loop in that mode) is gateway-only too.
- **In-flight token rejection**: v0.3.x JWTs lack `jti`; `Claims.jti` is now
  `#[serde(default)]`.
- Post-login redirects unified on `config::default_redirect()`; the
  already-authenticated login-page bounce no longer hardcodes `/app`. Admin
  routes degrade to 503 instead of a 500 extraction error without a database.

Deliberate deviations pinned in tests rather than reverted: SMTP failure
returns 200 and logs the magic link (production concern flagged for
follow-up), and the additive `X-User-Id`/`X-User-Email` headers, where
`X-User-Id` carries the email.

Test architecture: `src/app.rs` exposes `configure_routes()` /
`build_renderer()` / `AppSettings`; `tests/common/mod.rs` builds the real app
in-process with an in-memory session store, SMTP pointed at a closed port,
and a real echo upstream (`actix-test`). 14 magic-link-only contract tests +
3 gateway-mode tests all pass; clippy `-D warnings` and `cargo fmt --check`
clean (both were failing on the branch before).

Verification on aibox (deployed from the newly configured Mac workstation via
verbatime's `bootstrap_intranet_gcs.sh`): route matrix identical before and
after upgrading `145b99f` → `a8d0c42` (public root 200, gated paths 302 →
`/login.html`, Google OIDC 302 with PKCE, JWKS 501), 2 registered users
intact, and both auth methods confirmed live by a real login (magic link and
Google sign-in with a registered account).

Also adopted this session: `RUN` ticket prefix with `docs/NEXT-TICKET`
(seeded RUN-0005), the `docs/implementation/{backlog,done}` plan workflow,
and `docs/howto/fronting-a-service.md` for onboarding aicognito.

## Links

- Plan: `docs/implementation/backlog/2026-08-09-run-0004-magic-link-backward-compat.md`
- Onboarding guide: `docs/howto/fronting-a-service.md`
- Contract docs: `docs/howto/magic-link-only-mode.md`, `docs/howto/gateway-mode.md`
- Acceptance criterion: `docs/runegate-change-request.md`
- Commits: `cc2870a` (style), `6a316a3` (compat fixes + app factory),
  `826376b` (tests), `a8d0c42` (docs/conventions)
