# Fronting a service with Runegate

How to put Runegate in front of a web application, distilled from the first
production integration (verbatime) and written for the next one (aicognito).
Complements [magic-link-only-mode.md](magic-link-only-mode.md) and
[gateway-mode.md](gateway-mode.md), which describe the two operational modes;
this guide covers everything *around* Runegate: reverse-proxy routing, the
contract the fronted app must implement, Google OIDC setup, and deployment
ordering.

Verbatime file references below are to its
`feature/VTIME-94-account-registration` branch.

## 1. Topology

Runegate is a reverse proxy: every gated request traverses it, and it forwards
authenticated traffic to a single target service.

```
client → edge nginx (TLS) ──► runegate :7870 ──► app frontend (target service)
                    │                                  │
                    └─► direct bypasses                └─► app APIs (inner hops)
                        (heavy data paths)
```

Key facts that shape the routing:

- Runegate has **one** target (`RUNEGATE_TARGET_SERVICE`). Additional backends
  (APIs, upload servers) are either reached *through the app* (BFF pattern) or
  routed around Runegate by nginx.
- Runegate serves its own auth surface (`/auth/*`, `/login*`, `/mfa*`,
  `/keys/*`, `/static/*`, `/img/*`, `/health`) — nginx must send those paths to
  Runegate, not the app.
- In **gateway mode**, `/`, `/favicon.ico`, `/favicon.svg`, and `/_app/*` are
  proxied to the app *without* authentication (public landing page). In
  **magic-link-only mode** those paths require a session, exactly like the
  published v0.3.x release. Pick the mode accordingly.

Verbatime's production chain adds a second nginx on an intranet box behind
WireGuard (`verbatime/docs/tasks/ad-interim-intranet-deployment.md`); that is a
verbatime deployment detail, not part of the Runegate contract.

## 2. Runegate configuration

Full variable reference: `.env.example` in the repo root. The set verbatime
runs in production (`verbatime/infra/ansible/roles/runegate/templates/runegate.service.j2`):

| Variable | Verbatime value | Notes |
|---|---|---|
| `RUNEGATE_ENV` | `production` | Makes JWT/session secrets mandatory; secure cookies default on |
| `RUNEGATE_MODE` | `gateway` | Public landing page + OIDC/MFA surface |
| `RUNEGATE_SIGNUP_POLICY` | `open` | `invite_only` needs `DATABASE_URL` and the admin API |
| `DATABASE_URL` | `postgresql://…@localhost/runegate` | A **separate** `runegate` database, not the app's |
| `RUNEGATE_JWT_SECRET` | vault secret | ≥ 32 bytes |
| `RUNEGATE_SESSION_KEY` | vault secret | ≥ 64 bytes (128 hex chars preferred) |
| `RUNEGATE_SECURE_COOKIE` | `false` (intranet HTTP) | **Must be `true`/unset behind TLS** |
| `RUNEGATE_BASE_URL` | public origin of the edge | Magic-link URLs are minted from this — it must be what *users* can reach, not Runegate's own port |
| `RUNEGATE_TARGET_SERVICE` | `http://127.0.0.1:3000` | The app frontend |
| `RUNEGATE_SESSION_COOKIE_NAME` | `runegate_id` | |
| `RUNEGATE_DEFAULT_REDIRECT` | `/app` | Post-login landing path; defaults to `/proxy/` |
| `RUNEGATE_GOOGLE_CLIENT_ID/SECRET/REDIRECT_URL` | vault secrets | All three or OIDC stays off; delivered via `EnvironmentFile=/etc/runegate/runegate.env` (0640) |

Plus `config/email.toml` (SMTP credentials and the magic-link mail template —
`config/email.toml.example`; deployed to `/etc/runegate/config/email.toml`).

Operational gotchas learned the hard way:

- **Working directory matters.** With `RUNEGATE_AUTH_UI_MODE=static` (the
  default) and no `RUNEGATE_LOGIN_ASSETS_DIR`, Runegate serves login assets
  from the CWD-relative `static/` directory (falling back to
  `/opt/runegate/static`). Verbatime once pointed the systemd
  `WorkingDirectory` at the wrong place and got an infinite redirect loop into
  a 404 login page (`verbatime/docs/journal/2026-06/2026-06-15-12-07-runegate-integration-and-route-verification.md`).
  Set `RUNEGATE_LOGIN_ASSETS_DIR` explicitly in deployments.
- **`REDIS_URL` is a commitment.** If set and Redis is down, Runegate panics at
  startup rather than silently degrading. Only set it when Redis is genuinely
  provisioned (verbatime does not use Redis at all).
- **Compile-time DB checks.** Building with sqlx requires `DATABASE_URL` to
  point at a live database with migrations applied — create the `runegate`
  database *before* `cargo build --release` in any provisioning pipeline
  (`verbatime/infra/ansible/roles/runegate/tasks/main.yml`).

## 3. Google OIDC setup (Google Cloud Console)

Follow `verbatime/docs/tasks/google-sign-in.md` for the annotated version:

1. Create/select a project → **OAuth consent screen**: app name, support
   email; scopes `openid`, `userinfo.email`, `userinfo.profile`.
2. **Credentials → Create OAuth Client ID → Web application**:
   - Authorized JavaScript origins: `http://localhost:7870` (dev), the public
     origin (prod).
   - Authorized redirect URIs: `<origin>/auth/google/callback` — one entry
     **per public domain**. Never derive the redirect host from the incoming
     request; select it from server-side config keyed on `Host`
     (`verbatime/docs/design/landing_page/runegate-verbatime-multidomain-handoff-design.md`).
3. Put the three `RUNEGATE_GOOGLE_*` values in the environment file (dev: a
   gitignored `runegate.env`; prod: `/etc/runegate/runegate.env` via
   `ansible-vault`).
4. Verify: the startup log prints
   `Google OIDC configuration loaded successfully from environment`.
   If any of the three is missing, `/auth/google/*` answers 500
   "Google OIDC not configured".

## 4. Reverse-proxy (nginx) routing

Adapt verbatime's `infra/ansible/roles/frontend_deploy/templates/nginx-intranet.conf.j2`.
Three route classes:

1. **Runegate's own surface** → Runegate (`:7870`):
   `/`, `/login`, `/login.html`, `/auth/*`, `/mfa/*`, `/admin/*`,
   `/upload-ticket`, `/keys/*`, `/static/*`, `/img/*`. Include WebSocket
   upgrade headers if the app uses them.
2. **Gated app paths** → Runegate (which proxies to the app after auth). For
   verbatime: `/app`, `/p/*`, `/new`, `/api/*`. Define your own list for
   aicognito — the safest posture is "everything not explicitly public goes
   through Runegate".
3. **Deliberate bypasses** → straight to a backend, skipping auth. Verbatime
   sends `/media/*` to its API and `/tus/*` to tusd (uploads need unbuffered
   proxying, unlimited body size, day-long timeouts — traits you do not want
   on an auth proxy). Every bypass is an **unauthenticated** data path: keep
   the list short, written down, and justified.

The app's public static assets (`/_app/*`, favicons for a SvelteKit app) can go
directly to the app or through Runegate in gateway mode — both work; direct is
cheaper.

## 5. The fronted-app contract

### Identity headers

For authenticated requests Runegate strips any client-supplied copies and
injects (`src/proxy.rs`):

| Header | Value |
|---|---|
| `X-Runegate-Authenticated` | `true` / `false` |
| `X-Runegate-User`, `X-Forwarded-User`, `X-Forwarded-Email`, `X-User-Email` | the user's email |
| `X-User-Id` | **also the email** — not a UUID. Treat it as an opaque, stable string |

Rules for the app:

- Trust these headers **only** on the network path from Runegate; every
  internet-facing route must go through the gate or explicitly not rely on
  them.
- Fail closed when they're absent (verbatime:
  `apps/video-app/src/hooks.server.ts`).
- Re-inject identity on inner hops yourself: Runegate decorates only the
  outermost request. Verbatime's SvelteKit server re-adds the headers when it
  calls its Rust API (BFF pattern).
- Headers can't ride on `EventSource`/SSE requests made by the browser to a
  bypassed backend. Verbatime patched around this with a `?user_id=` query
  fallback — that is an auth hole; route SSE through the gated app instead.
- `X-User-Name` / `X-User-Mfa` appear in verbatime's dev mocks but are **not**
  sent by the real gateway today. Don't depend on them.

### Account provisioning

Registration/login state lives in Runegate. The app provisions its own profile
row lazily on first authenticated request, in one transaction, keyed on the
Runegate subject (store it as an opaque string column):

1. Look up profile by `X-User-Id`; if present, done.
2. Require `X-User-Email`; on conflict with an existing profile under a
   different subject, answer **409** and do not merge silently.
3. Insert profile (+ any starter entitlements) atomically.

(Verbatime: `services/rs/verbatime-api/src/projects/router.rs`; design record
`verbatime/docs/design/registration/auth-and-registration-design.md`. Skip its
legacy shadow `auth_user` table — that's a leftover, not part of the contract.)

### Links and pages

- Login/register links: `/auth/login?return_to=<path>` and
  `/auth/register?return_to=<path>`. An already-authenticated visitor to
  those pages is bounced to `return_to` (default: `RUNEGATE_DEFAULT_REDIRECT`).
- The magic-link flow posts to `/auth/identify` then `/auth/magic/start`
  (JSON bodies); the wire contract types live in
  `verbatime/apps/runegate-auth/contract/gateway-contract.ts`.
- A custom auth UI is a static bundle dropped into Runegate's login-assets
  directory (verbatime builds `apps/runegate-auth` with SvelteKit
  `adapter-static`, base path `/auth`, and rsyncs it into
  `/opt/runegate/static/`). Without one, Runegate's built-in `static/`
  login page is used.
- **Logout does not exist yet.** The design calls for a CSRF-protected
  `POST /auth/logout`; nothing implements or links it. Plan for session expiry
  in the meantime.

## 6. Deployment order

From verbatime's Ansible playbook (`infra/ansible/playbooks/intranet-deployment.yml`),
generalized:

1. System packages, service user, (Rust toolchain if building from source).
2. PostgreSQL up; create the **`runegate` database** (separate from the app's).
3. Build Runegate with `DATABASE_URL` exported (sqlx compile-time checks);
   install the binary.
4. Install `/etc/runegate/config/email.toml`, `/etc/runegate/runegate.env`
   (secrets, 0640), and the systemd unit — set `WorkingDirectory` and/or
   `RUNEGATE_LOGIN_ASSETS_DIR` correctly (see §2).
5. Deploy the auth UI bundle into the login-assets directory **before or
   together with** starting Runegate (verbatime starts Runegate one role
   before the assets are copied — on a fresh host there's a window where
   `/login.html` 404s).
6. Build/start the app; install the nginx site; reload nginx.
7. Smoke-test: `GET /health` → 200; anonymous gated path → 302 to login;
   magic-link roundtrip; Google button (if enabled) lands on
   `RUNEGATE_DEFAULT_REDIRECT`.

## 7. Onboarding checklist for aicognito

- [ ] Choose the mode: public landing page? → `gateway`; purely private
      service → `magic-link-only` (no `RUNEGATE_MODE`, no DB needed).
- [ ] Pick the gated-path list and (only if unavoidable) the bypass list.
- [ ] Create the `runegate` Postgres database (gateway mode).
- [ ] Mint `RUNEGATE_JWT_SECRET` / `RUNEGATE_SESSION_KEY`; vault them.
- [ ] Google OAuth client with one redirect URI per public domain (optional).
- [ ] SMTP account + `email.toml`.
- [ ] Implement the header contract: fail-closed parsing, opaque
      `X-User-Id`, lazy provisioning with 409 on email collision.
- [ ] Set `RUNEGATE_DEFAULT_REDIRECT` to the app's post-login path.
- [ ] Auth UI: reuse Runegate's built-in static page first; brand later.
- [ ] Don't copy from verbatime: the `dev_session` cookie bypass, hardcoded
      dev user ids, the SSE `?user_id=` fallback, the shadow `auth_user`
      table, `RUNEGATE_SECURE_COOKIE=false`.
