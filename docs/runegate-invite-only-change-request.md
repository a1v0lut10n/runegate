# Runegate Change Request (CR): Invite‑Only Sign‑Up

**Owner:** Aivolution (Runegate maintainers)  
**Date:** 2025-09-20  
**Status:** Proposal (for review)  
**Scope:** Add **invite-only** account creation to Runegate, compatible with existing magic-link and Google SSO flows. Works in single app / single domain deployments. Backward compatible with today’s behavior.

---

## 1) Summary & Goals

Introduce an **invite-only** signup policy so **new accounts can be created only when a valid invite is presented**. The feature must:

- Work with both **Magic Link** (passwordless email) and **Google SSO** first‑login flows.  
- Support single‑use or N‑use invites, TTLs, revocation, and **optional scope** (exact email, domain, or project).  
- Avoid **user enumeration** and keep responses uniform.  
- Remain **backward compatible**: keep current “open signup” behavior unless explicitly enabled.

**Non-goals:** A full admin dashboard UI, complex role management, multi‑tenant policy engines. (CLI/API is sufficient.)

---

## 2) Modes & Config (Backward Compatible)

### 2.1 New signup policy flag
Add `RUNEGATE_SIGNUP_POLICY` with values:

- `open` *(default; current behavior)* — Any email may create a new account (subject to email verification/MFA).  
- `invite_only` — New accounts require a valid invite; existing accounts sign in as usual.  
- `domain_allowlist` *(optional future)* — Only emails from an allowlisted domain may create accounts.

> If unset, default to `open` to preserve existing behavior.

### 2.2 Supporting environment variables
- `RUNEGATE_INVITE_DEFAULT_TTL_SECONDS` (default: `1209600` i.e., 14 days)  
- `RUNEGATE_INVITE_DEFAULT_MAX_USES` (default: `1`)  
- `RUNEGATE_DOMAIN_ALLOWLIST` (CSV; used only if `domain_allowlist` is enabled)  
- `RUNEGATE_ADMIN_API_TOKEN` (static bearer token for admin endpoints)  
- *(Existing)* `RUNEGATE_LOGIN_ASSETS_DIR` / `RUNEGATE_LOGIN_ASSETS_URL` continue to control the login/registration UI origin.

---

## 3) Data Model (Postgres)

```sql
-- Invites master table
CREATE TABLE invites (
  id            BIGSERIAL PRIMARY KEY,
  code          TEXT UNIQUE NOT NULL,        -- URL-safe random (>=128 bits entropy)
  created_by    TEXT NOT NULL,               -- admin identifier (email or user id)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ NOT NULL,
  max_uses      INT NOT NULL DEFAULT 1,
  used_count    INT NOT NULL DEFAULT 0,
  status        TEXT NOT NULL CHECK (status IN ('active','revoked','expired')),
  scope_json    JSONB NOT NULL DEFAULT '{}'  -- e.g., {"email":"alice@org.com"} or {"domain":"org.com"} or {"project_id":"prj_123"}
);

-- Audit of invite redemptions
CREATE TABLE invite_usages (
  id          BIGSERIAL PRIMARY KEY,
  invite_id   BIGINT NOT NULL REFERENCES invites(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  used_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip          INET,
  user_agent  TEXT
);

-- Recommended indexes
CREATE INDEX ON invites (status);
CREATE INDEX ON invites (expires_at);
```

**Notes**  
- `expires_at` is authoritative; scheduled job (or query logic) marks as `expired` after the timestamp.  
- For scope, support keys: `email`, `domain`, `project_id` (extensible).  
- Increment `used_count` atomically when consuming the invite to prevent oversubscription.

**Redis (ephemeral)**  
- Optional cache for invite lookups and rate limits. No schema changes required.

---

## 4) Admin API (minimal, secure)

All endpoints require `Authorization: Bearer ${RUNEGATE_ADMIN_API_TOKEN}` or mTLS. Intended for CLI/automation.

```
POST   /admin/invites
GET    /admin/invites?status=active&email=alice@org.com&domain=org.com
POST   /admin/invites/{id}/revoke
```

### 4.1 Create Invite
**Request**
```json
{
  "email": "optional exact email",
  "domain": "optional-domain.com",
  "project_id": "optional",
  "max_uses": 1,
  "ttl_seconds": 1209600
}
```
**Response**
```json
{
  "id": 42,
  "code": "pOQd...",
  "invite_url": "https://id.example.com/auth/invite?code=pOQd...",
  "expires_at": "2025-10-04T12:00:00Z",
  "max_uses": 1
}
```

### 4.2 Revoke Invite
`POST /admin/invites/{id}/revoke` → `200 { status: "revoked" }`

---

## 5) Public HTTP Surface (unchanged routes + new)

```
GET  /auth/login                       # existing; serves UI per RUNEGATE_LOGIN_ASSETS_*
GET  /auth/register                    # optional route; same UI engine in 'register' mode
POST /auth/identify                    # identifier-first; uniform response (no enumeration)
POST /auth/magic/start                 # device-bind + send magic link (if allowed)
GET  /auth/magic/consume               # consume link → PREAUTH

# Google SSO (if enabled)
GET  /auth/google/start
GET  /auth/google/callback

# NEW: invite landing
GET  /auth/invite                      # ?code=... → sets short-lived invite cookie and redirects

# MFA and sessions (existing per gateway mode design)
GET  /mfa
POST /mfa/...                          # webauthn/totp endpoints
POST /auth/logout
```

**Behavior gated by `RUNEGATE_SIGNUP_POLICY`:**
- `open`: new users proceed as usual.  
- `invite_only`: first-time users **must** present invite (via code or cookie). Existing users unaffected.  
- `domain_allowlist` (future): first-time users must match allowlisted domains.

---

## 6) Flows

### 6.1 Magic Link (invite-only first login)
1) User enters email on `/auth/login`.  
2) Server checks:  
   - If **existing user** → proceed (send magic link).  
   - If **new user** and policy=`invite_only` → require invite:  
     - If request has `invite_code` **or** an **invite cookie** set by `/auth/invite`, accept and **send magic link**.  
     - Else respond uniformly (“If eligible, we’ve sent a link”) but *do not send*; UI may prompt for invite code.

3) On `GET /auth/magic/consume`, issue **PREAUTH**, redirect `/mfa` (enroll or challenge), then rotate to **SESSION** on success.  
4) After first successful login, **increment** invite usage; if `max_uses` reached, mark as used.

### 6.2 Google SSO (invite-only first login)
- After callback, if user exists → PREAUTH → `/mfa`.  
- If new and policy=`invite_only`:  
  - Look up active invite matching `scope.email` or `scope.domain`.  
  - If found → create user, record usage, PREAUTH → `/mfa`.  
  - If not → show “Invite required” page (no account created).

### 6.3 Invite Landing
- `GET /auth/invite?code=...`  
  - Validate invite (status, TTL, uses, scope).  
  - Set **invite cookie** (HttpOnly, Secure, TTL 10–15 min).  
  - Redirect to `/auth/login?invite=1` with “Invite applied” banner.

**Privacy:** Avoid user enumeration by keeping responses/timings uniform in `/auth/identify` whether an invite exists or not.

---

## 7) Validation Rules

An invite is valid iff:
- `status='active'` and `now < expires_at` and `used_count < max_uses`, and  
- **Scope check passes**:  
  - `scope.email` → email must match exactly.  
  - else if `scope.domain` → email domain must match.  
  - else **unscoped** (accept any email).

**Atomicity:** Increment `used_count` in the same transaction that creates the user (or transitions first PREAUTH) to prevent double‑use in races.

---

## 8) Security & Anti‑Abuse

- **No user enumeration:** Uniform messages and jittered response times.  
- **Rate limits:** per IP & per email on `/auth/identify`, `/auth/invite`, and Google callback.  
- **Device binding:** Keep magic link device‑bind cookie.  
- **Revocation:** Revoke blocks new redemptions (existing users unaffected).  
- **Audit:** Log invite creation, revocation, and usage (email, invite id, IP, UA).  
- **Captcha (optional):** Enable after N failed identify attempts.

---

## 9) UI Notes

- On `/auth/login`, when policy=`invite_only` and no invite present, show **“Have an invite code?”** input.  
- If landing via `/auth/invite`, show **“Invite applied”** badge and hide code input.  
- Google SSO fallback page: “You’ll need an invite to join. Ask an admin.”  
- **Asset origin:** UI continues to be served from `RUNEGATE_LOGIN_ASSETS_DIR` or `RUNEGATE_LOGIN_ASSETS_URL` (CDN).

---

## 10) Incremental Development Plan

### Sprint 0 — Schema & Flags
- [ ] Add Postgres tables `invites`, `invite_usages`.  
- [ ] Add `RUNEGATE_SIGNUP_POLICY` and keep default `open`.  
- [ ] Wire config gating (code paths no‑op when `open`).

### Sprint 1 — Admin API
- [ ] Implement `POST /admin/invites`, `GET /admin/invites`, `POST /admin/invites/{id}/revoke`.  
- [ ] Gate with `RUNEGATE_ADMIN_API_TOKEN` or mTLS.

### Sprint 2 — Public Flows
- [ ] Implement `GET /auth/invite` (landing + invite cookie).  
- [ ] Update `/auth/identify` to require invite when creating new users.  
- [ ] Update Google callback path to check invite for new users.

### Sprint 3 — UI & Copy
- [ ] Add invite code input to login page (only when policy=`invite_only`).  
- [ ] Add “Invite applied” banner; polish messages.

### Sprint 4 — Hardening & QA
- [ ] Add jittered uniform responses; rate limits; audit logs.  
- [ ] Atomic increment of `used_count`.  
- [ ] Unit/integration tests and staging flip to `invite_only`.

---

## 11) Test Cases

- ✅ Valid single‑use invite → new user via magic link; second attempt fails.  
- ✅ Domain‑scoped invite → multiple users at domain succeed until `max_uses` reached.  
- ✅ Expired / revoked invite blocks first‑time login; existing accounts unaffected.  
- ✅ Google SSO + invite present → user created; without invite → blocked.  
- ✅ Race across two clients → only one consumes (check `used_count`).  
- ✅ `/auth/identify` timing/messages uniform with/without invite.  
- ✅ Logs include creation, usage, and revocation with actor/IP/UA.

---

## 12) Acceptance Criteria

- With `RUNEGATE_SIGNUP_POLICY=open`, behavior is unchanged from current release.  
- With `invite_only`, a first‑time user **cannot** create an account without a valid invite, via either Magic Link or Google SSO.  
- Admin can create/revoke invites and see active ones.  
- Invite landing sets a short‑lived invite cookie and enables the identify flow.  
- All flows avoid user enumeration and pass the listed test cases.

---

## 13) Operational Notes

- **Rotation:** Invite codes are random; no reuse across environments.  
- **Secrets:** Protect `RUNEGATE_ADMIN_API_TOKEN`.  
- **Observability:** Counters for invites created/used/expired/revoked; alerts on unusual spikes.  
- **Docs:** Update README with policy flag and admin API examples.
