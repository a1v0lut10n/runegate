---
date: 2026-08-09
type: design
status: proposed
components: []
aspects: []
tags: [aicognito, oidc, tokens, authn]
---

# Runegate fronts AICognito as a token issuer, not a reverse proxy

## Context

AICognito — the planned git-server backend hosting aicogito "minds" — needs
authentication. Its architecture (aicognito
`docs/architecture/aicognito-architecture.md`) draws a hard line: Runegate
owns authentication (IdP interaction, MFA, token issuance), AICognito owns
authorization (orgs, teams, repo roles). The "Runegate ↔ AICognito
authentication/token contract" is that architecture's highest-priority
unwritten design doc.

The forces:

- **The primary clients cannot do browser auth.** aicogito shells out to the
  `git` binary (with `GIT_TERMINAL_PROMPT=0`) for clone/fetch/push. A session
  cookie or a 302 to `/login.html` — Runegate's entire auth model today — is
  a hard failure on `/info/refs`. The architecture prescribes a git
  credential helper feeding short-lived tokens as HTTP Basic passwords.
- **Git Smart HTTP must stream.** Packfile transfers are large, unbuffered,
  and long-lived. Verbatime's deployment deliberately routes such traffic
  *around* Runegate; putting an auth proxy in this data path is a known
  anti-pattern from the first integration.
- **Runegate proxies exactly one target.** AICognito is role-split
  (api/git/ui), a poor fit for the single-`RUNEGATE_TARGET_SERVICE` model.
- **Identity must be durable and non-email.** The architecture forbids email
  as an authorization key; Runegate's current headers and upload tickets
  carry the email as subject (`X-User-Id` is the email). Gateway mode
  already has PostgreSQL `users.id` UUIDs to use instead.
- Runegate v0.4.0 already contains the embryo of a token service:
  `POST /upload-ticket` mints RS256 JWTs for an authenticated session, and
  `/keys/upload_jwks.json` publishes verification keys.

## Decision

Runegate acts as AICognito's **authorization server** (OAuth2/OIDC-style
token issuer). It never proxies AICognito traffic.

1. **Runegate keeps serving the authentication pages** (magic link, Google
   OIDC, future MFA) at its own origin, exactly as in gateway mode today.
2. **A new token surface** is added to Runegate: an authorize endpoint
   (Authorization Code + PKCE), a token endpoint (code exchange and refresh),
   the device-authorization flow for headless clients, issuer metadata
   discovery, and a first-class JWKS (generalizing the upload-ticket keys).
3. **Access tokens are short-lived RS256 JWTs** with `iss`, `aud`,
   `exp`/`iat`, `scope`, and **`sub` = Runegate's `users.id` UUID** — never
   the email, which travels as an ordinary claim.
4. **AICognito validates tokens locally** against Runegate's JWKS (no
   per-request calls to Runegate) and implements all authorization itself.
5. **Git flows**: `aicognito auth login` opens the system browser at
   Runegate's authorize endpoint; the credential helper supplies
   `username=oauth2` / `password=<access-token>` to git; git talks directly
   to AICognito's gateway. Runegate is not in the data path.
6. **Verbatime's proxy-mode integration is untouched**; the token surface is
   additive and requires gateway mode + PostgreSQL.

## Alternatives considered

- **Full reverse proxy (the verbatime model).** Rejected: puts the auth
  proxy inside unbuffered, long-lived packfile transfers; fights the
  single-target proxy design; every "bypass for streaming" carve-out is an
  unauthenticated hole; header-based identity contradicts the non-email
  subject requirement.
- **Hybrid — sessions+headers for the UI, tokens only for git.** Rejected:
  two identity models to keep consistent; AICognito's web UI can simply be
  another OAuth client of Runegate.
- **AICognito talks to Google directly (no Runegate).** Rejected: loses
  magic-link auth, invite-only onboarding, MFA ownership, and centralized
  identity across fronted services; every future service would re-implement
  IdP wiring.

## Consequences

Easier:
- AICognito verifies identity offline and scales horizontally without an
  auth-proxy chokepoint; no streaming/timeout coupling to Runegate.
- Clean, testable contract (token claims + JWKS) instead of an implicit
  header contract; the authN/authZ boundary matches the written architecture.
- Runegate's deployment footprint for AICognito is small: auth pages and
  token endpoints only.

Harder / newly required:
- Runegate must grow real authorization-server machinery: PKCE, refresh-token
  storage with rotation and revocation (new PostgreSQL tables), signing-key
  management and rotation behind the JWKS, issuer metadata, client
  registration for at least `aicognito-cli` and the AICognito web UI.
- AICognito must implement JWT validation, the `aicognito credential`
  helper, and PKCE/device login flows (already in its architecture).
- Revocation latency is bounded by the access-token TTL; compromised tokens
  live until expiry (mitigated by short TTLs, e.g. ~15 minutes).
- Token TTLs and the scope vocabulary (e.g. `git.read`, `git.write`,
  `repo.admin`) are contract details still to pin in the implementation
  plan; the cross-repo contract should also be registered in
  aivolution-meta's `docs/reference/contracts/` once accepted.

## Links

- Authoritative contract: aicognito
  `docs/architecture/runegate-aicognito-auth-token-contract.md`
- Implementation plan: `../implementation/backlog/2026-08-09-run-0005-aicognito-auth-token-contract.md`
- AICognito architecture: aicognito `docs/architecture/aicognito-architecture.md`
- First-integration lessons: `../howto/fronting-a-service.md`
