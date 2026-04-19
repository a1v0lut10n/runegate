# Runegate Change Request (CR): Passwordless Auth Gateway with Google SSO, MFA, and Upload Tickets

**Owner:** Aivolution (Runegate maintainers)  
**Date:** 2025‑09‑20  
**Status:** Proposal (for review)  
**Scope:** Single app / single domain, minimal moving parts. Preserve current “magic link only” behavior as a mode.

---

## 1) Summary & Goals

Enhance **Runegate** from a magic‑link gateway into a **passwordless auth gateway** that supports:

1. **Hardened magic links** (device‑binding, short TTL, single‑use).  
2. **Google OAuth (OIDC) sign‑in** using Authorization Code + PKCE (server‑side).  
3. **Mandatory MFA on first login** with **WebAuthn (passkeys)** preferred and **TOTP** fallback, plus **backup codes**.  
4. **Upload tickets (JWT)** for large media uploads to GCS via tusd/Uppy, with two issuance models:  
   - **App‑minted**: the app BFF mints the ticket based on identity headers from Runegate.  
   - **Runegate‑minted**: Runegate exposes **`POST /upload-ticket`** to mint short‑lived tickets.
5. **UI decoupling**: allow the login/registration/MFA UI to be served from a configurable location (on‑disk dir or external CDN), while keeping the *current static approach working by default*.
6. **Backward compatibility**: retain today’s “magic‑link only” flow as a **mode** selectable by environment variable.

**Non‑goals:** Becoming a full OIDC Provider for multiple client apps, consent screens, refresh token service, or centralized billing/entitlement logic.

---

## 2) Modes of Operation (Backward Compatible)

Introduce `RUNEGATE_MODE` with the following values:

- `magic-link-only` *(default = current behavior)*  
  - Single field for email, send magic link, establish session after link.  
  - No Google SSO or MFA enforcement.
- `gateway` *(new)*  
  - Identifier‑first flow; supports magic link **and** Google SSO.  
  - Enforces **MFA on first login** (WebAuthn preferred, TOTP fallback).  
  - Injects identity headers to the single upstream app.  
  - Optionally exposes `/upload-ticket` (or the app mints tickets).

> All new features must be *no‑ops* in `magic-link-only` mode.

---

## 3) User Flows (Gateway Mode)

### 3.1 Identifier‑First (no user enumeration)
- UI posts to `POST /auth/identify { email, invite_code? }`  
- Server responds uniformly (e.g., “Check your email for a link”) regardless of account existence/policy.  
- If policy allows, enqueue a **single‑use magic link** *(TTL 5–10 min)* and set a short‑lived **device‑bind cookie**.

### 3.2 Magic Link Consume
- `GET /auth/magic/consume?jti=…` verifies JTI + device‑cookie.  
- Issues **PREAUTH** cookie (short TTL, ~10–15 min).  
- Redirects to `/mfa` (enrollment if first login, or challenge if already enrolled).

### 3.3 Google Sign‑In
- `GET /auth/google/start` → OIDC with PKCE; `GET /auth/google/callback` exchanges code server‑side.  
- On success: **PREAUTH** and redirect to `/mfa`.  
- If user doesn’t exist and policy allows: create user record before PREAUTH.

### 3.4 MFA on First Login
- **Preferred**: WebAuthn enrollment (attestation = none, UV required).  
- **Fallback**: TOTP (QR, confirm 2 codes), plus **backup codes**.  
- After a successful factor: rotate **PREAUTH → SESSION** (full session, 8–24h TTL).  
- Include `amr` (e.g., `["email","webauthn"]`) in session claims.  
- Proxy allows upstream only with **full SESSION**.

---

## 4) HTTP Surface (Gateway Mode)

```
GET  /auth/login                      # serves UI (configurable location)
GET  /auth/register                   # same component (register mode), optional

POST /auth/identify                   # { email, invite_code? } → uniform response
POST /auth/magic/start                # starts device-binding + emails link
GET  /auth/magic/consume              # verifies link + device cookie → PREAUTH

GET  /auth/google/start               # begin Google OIDC (code+PKCE)
GET  /auth/google/callback            # exchange code → PREAUTH

GET  /mfa                             # enrollment or challenge screen
POST /mfa/webauthn/attestation/options
POST /mfa/webauthn/attestation/finish
POST /mfa/verify/webauthn
POST /mfa/totp/start
POST /mfa/totp/confirm
POST /mfa/backup-codes/regenerate

POST /upload-ticket                   # (optional) mint short-lived JWT for tusd/GCS
POST /auth/logout
GET  /healthz
```

**Identity headers to upstream (unchanged / extended):**  
`X-User-Id`, `X-User-Email`, `X-User-AMR` and **never** forward the session cookie upstream.

---

## 5) Upload Tickets (JWT for Uppy + tusd)

Two issuance models supported:

### 5.1 App‑minted (simple)
- App BFF reads `X-User-*` headers from Runegate.
- App mints a JWT (10–15 min TTL) for tusd and returns it to the browser.  
- tusd **pre-create hook** calls back into the app to validate the token and enforce policy (project, max size, MIME).

### 5.2 Runegate‑minted (centralized)
- `POST /upload-ticket { projectId, maxMb, mime? }` → JWT short TTL.  
- Publish a **JWKS** at `/keys/upload_jwks.json` or provide a private verification endpoint `/internal/verify-upload-ticket`.  
- tusd hook validates signature (JWKS) or calls verification endpoint.

**JWT claims (suggested):**
```json
{
  "iss": "id.example.com",
  "aud": "tusd",
  "sub": "user_123",
  "prj": "project_456",
  "allow": { "mime": ["video/*","audio/*"], "max_mb": 20000 },
  "prefix": "projects/456/uploads/${date}",
  "jti": "uuid",
  "iat": 1737427200,
  "nbf": 1737427200,
  "exp": 1737428100
}
```

---

## 6) Configuration (new/updated env vars)

- **Modes & UI**
  - `RUNEGATE_MODE` = `magic-link-only` | `gateway` *(default: magic-link-only)*
  - `RUNEGATE_LOGIN_ASSETS_DIR` = `/opt/runegate/static` *(default current)*
  - `RUNEGATE_LOGIN_ASSETS_URL` = `https://assets.example.com/runegate-auth/vX/` *(optional CDN)*

- **Magic Links**
  - `RUNEGATE_MAGIC_LINK_TTL_SECONDS` *(default 600)*
  - `RUNEGATE_DEVICE_BIND_TTL_SECONDS` *(default 600)*
  - `RUNEGATE_RETURN_TO_ALLOWLIST` *(CSV of allowed paths/origins)*
  - `RUNEGATE_INVITE_REQUIRED` = `true|false` *(default false)*
  - `RUNEGATE_DOMAIN_ALLOWLIST` = `example.com,example.org`

- **Google OIDC**
  - `RUNEGATE_GOOGLE_CLIENT_ID`
  - `RUNEGATE_GOOGLE_CLIENT_SECRET`
  - `RUNEGATE_OIDC_REDIRECT_URI` = `https://id.example.com/auth/google/callback`

- **MFA**
  - `RUNEGATE_WEBAUTHN_RP_ID` = `id.example.com`
  - `RUNEGATE_WEBAUTHN_ORIGINS` = `https://id.example.com,https://id.example.test`
  - `RUNEGATE_TOTP_ENCRYPTION_KEY` *(server-side “pepper”)*
  - `RUNEGATE_MFA_REQUIRED` = `true` *(gateway mode default)*

- **Sessions & Cookies**
  - `RUNEGATE_COOKIE_DOMAIN` = `.example.com`
  - `RUNEGATE_SESSION_TTL_SECONDS` *(default 86400)*
  - `RUNEGATE_SESSION_SIGNING_KEY_PATH` *(Ed25519 or RSA)*

- **Persistence**
  - `DATABASE_URL` (Postgres)
  - `REDIS_URL`

- **Upload Tickets**
  - `RUNEGATE_UPLOAD_TICKET_ISSUER` = `id.example.com`
  - `RUNEGATE_UPLOAD_TICKET_JWKS_PATH` *(public JWKS for verification)*
  - `RUNEGATE_UPLOAD_TICKET_TTL_SECONDS` *(default 900)*

- **Rate Limits & Misc**
  - `RUNEGATE_RATE_LIMIT_LOGIN`, `RUNEGATE_RATE_LIMIT_MFA`
  - `RUNEGATE_CSP_EXTRA` *(allow CDN if assets served remotely)*

---

## 7) Data Model (minimal tables)

**Postgres**
- `users(id, email, created_at, email_verified_at, status)`
- `oauth_identities(user_id, provider, subject, linked_at)`
- `mfa_enrollments(id, user_id, type enum[webauthn, totp], label, added_at, meta_json)`  
  - WebAuthn: credential_id (b64), public_key, sign_count, transports, user_handle
  - TOTP: secret_enc, confirmed_at
- `backup_codes(user_id, code_hash, used_at)`
- `magic_links(jti, user_id or email, purpose, issued_at, expires_at, used_at)`
- `sessions(id, user_id, created_at, expires_at, ip, user_agent)` *(optional if fully stateless)*
- `audit(ts, actor, action, target, ip, ua, meta_json)`

**Redis**
- OAuth `state`/`nonce`, PKCE `code_verifier`
- Magic link JTI replay cache
- WebAuthn challenge cache
- TOTP enrollment temp
- Rate limits / attempt counters
- Device‑bind cookie state

---

## 8) Security Checklist

- **User enumeration**: uniform responses & timing; captcha after thresholds.  
- **Magic link hardening**: single‑use, short TTL, device‑binding or secondary on‑screen code.  
- **CSRF**: double‑submit cookie or Origin checks for all POSTs.  
- **Cookies**: HttpOnly, Secure, `SameSite=Lax`; do not forward to upstream.  
- **Redirects**: `return_to` allowlist only.  
- **MFA**: require at first login in `gateway` mode; allow multiple WebAuthn creds; include `amr` in session.  
- **Keys**: rotate session/upload‑JWT signing keys; expose JWKS for upload tickets if Runegate mints them.  
- **Logging/Audit**: login, factor add/remove, failed attempts, token issuance, new device.  
- **Rate limits**: per IP and per principal on `/auth/*` and `/mfa/*` routes.

---

## 9) Incremental Development Plan (sprints)

### Sprint 0 — Scaffolding & Modes
- [ ] Add `RUNEGATE_MODE` flag; ensure current behavior under `magic-link-only` remains identical.  
- [ ] Extract static UI serving into configurable `RUNEGATE_LOGIN_ASSETS_DIR` and optional `RUNEGATE_LOGIN_ASSETS_URL` (CDN).  
- [ ] Wire feature gating (routes no‑op in `magic-link-only`).

### Sprint 1 — Magic Link Hardening
- [ ] Implement `POST /auth/identify` (uniform responses).  
- [ ] Device‑binding cookie at `/auth/login` and verify at `/auth/magic/consume`.  
- [ ] Single‑use JTI with Redis; TTL configurable; add return_to allowlist.

### Sprint 2 — Google OIDC (server‑side)
- [ ] Routes: `/auth/google/start`, `/auth/google/callback`.  
- [ ] PKCE + state/nonce in Redis; ID token validation.  
- [ ] Create/link `oauth_identities`; emit **PREAUTH** cookie.

### Sprint 3 — Session Split & Gate
- [ ] Implement **PREAUTH** vs **SESSION** cookies + middleware that redirects to `/mfa` when MFA not satisfied.  
- [ ] Extend identity headers to include `X-User-AMR` when SESSION present.

### Sprint 4 — MFA: WebAuthn (preferred)
- [ ] Routes for attestation options/finish and assertion verify.  
- [ ] Store credential metadata; require UV; rotate PREAUTH → SESSION on success.  
- [ ] UI screens (from assets dir/URL).

### Sprint 5 — MFA: TOTP + Backup Codes
- [ ] TOTP start/confirm with encrypted secret & throttled verify.  
- [ ] One‑time backup codes (hashed), regenerate flow.

### Sprint 6 — Upload Tickets
- [ ] App‑minted path: document header contract and example validator for tusd hook.  
- [ ] Runegate‑minted path: `POST /upload-ticket`; implement signing key + JWKS at `/keys/upload_jwks.json`.  
- [ ] Add simple policy checks (size/mime/prefix) and JTI single‑use option.

### Sprint 7 — Documentation & Ops
- [ ] Env var reference; sample NGINX; CSP examples for CDN assets.  
- [ ] Migration notes from `magic-link-only` → `gateway`.  
- [ ] Example Svelte UI bundle and folder layout.

### Sprint 8 — QA & Hardening
- [ ] Rate‑limit configs; captcha hook after thresholds.  
- [ ] Pen‑test checklist; negative tests for enumeration and CSRF.  
- [ ] Load test large uploads in both issuance models (no Runegate in data path).

---

## 10) Acceptance Criteria

- Running with `RUNEGATE_MODE=magic-link-only` behaves exactly as today.  
- With `RUNEGATE_MODE=gateway` and Google creds set, a new user can:  
  1) Identify via email **or** sign in with Google.  
  2) Complete **MFA on first login** (WebAuthn or TOTP).  
  3) Receive a full session; upstream receives `X-User-*` headers.  
- Upload tickets can be obtained via app BFF **or** `POST /upload-ticket`; tusd hook validation example passes.  
- Login/registration UI can be served from `/opt/runegate/static` **or** a configured CDN URL with CSP adjusted accordingly.  
- Security controls (CSRF, rate limits, device‑binding, TTLs, allowlists) are present and documented.

---

## 11) Open Questions

1. Do we require **invite‑only** or **domain allowlist** at launch?  
2. Should Runegate publish **JWKS** for sessions as well (future IdP path), or only for upload tickets?  
3. Do we enforce **UV-required** for WebAuthn on all platforms, or allow “preferred” for older browsers?  
4. Where should the **audit log** be shipped (stdout vs. external sink)?  
5. Should we add an **admin API** to disable users / revoke sessions now or later?

---

## 12) Appendix — Example Headers & Policies

**Headers injected to upstream:**  
```
X-User-Id: user_123
X-User-Email: alice@example.com
X-User-AMR: ["email","webauthn"]
```

**Sample NGINX (if used in front of Runegate):**
```nginx
proxy_request_buffering off;
client_max_body_size 0;
proxy_read_timeout 1d;
```

**Suggested Cookie Flags:** HttpOnly, Secure, SameSite=Lax; rotate on privilege/AMR changes.
