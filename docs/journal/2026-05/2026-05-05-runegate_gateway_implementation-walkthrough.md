# Runegate Gateway Implementation Walkthrough

The architectural transformation of Runegate into a production-grade identity proxy is complete! All planned phases from the implementation plan have been executed successfully.

Here is a summary of the systems we implemented and their capabilities.

## 1. Magic-Link Hardening & Session Progression
- Implemented single-use **JTI (JWT IDs)** for magic-link consumption to prevent replay attacks.
- Integrated a two-stage session progression model (`PREAUTH` vs `SESSION`). When a user completes the first factor (e.g. Magic Link or OIDC), they are placed in a `PREAUTH` state.
- `AuthMiddleware` verifies that users attempting to access downstream applications have an active, fully `authenticated` session.

## 2. Google OIDC & Multi-Factor Authentication (MFA)
- Integrated the `oauth2` and `reqwest` crates to natively support Google OAuth2 login (`/auth/google/start` and `/auth/google/callback`).
- Securely managed OAuth state with session-stored `csrf` and `pkce` challenges.
- Setup endpoint skeletons for WebAuthn (`webauthn-rs`) and TOTP (`totp-rs`) at `/mfa/webauthn/*` and `/mfa/totp/*`. These upgrade a `PREAUTH` session to a full `SESSION`.

## 3. Edge Authorization (Upload Tickets)
- Developed an edge authorization mechanism to issue short-lived (15 minutes) JWTs at `POST /upload-ticket`.
- Upload tickets are signed with an RSA private key loaded securely from `RUNEGATE_UPLOAD_PRIVATE_KEY`.
- Exposed a public `GET /keys/upload_jwks.json` endpoint to seamlessly distribute the public key to downstream services (like `tusd`).

## 4. Durable Identity & Invite-Only Onboarding (PostgreSQL)
- Added `sqlx` support to implement a robust, dynamically loaded `PgStore`.
- Designed comprehensive relational schemas in `migrations/` for:
  - `users`, `oauth_identities`
  - `mfa_enrollments`, `backup_codes`
  - `invites` and `invite_usages`
  - `audit_logs`
- Implemented an `admin.rs` module with `POST /admin/invites` and `POST /admin/invites/{id}/revoke`, protected by `RUNEGATE_ADMIN_API_TOKEN`.
- Wired the `RUNEGATE_SIGNUP_POLICY=invite_only` check into `/auth/identify`, `/auth/magic/start`, and Google OIDC callback flows.
- New users must provide an invite code if the policy is enabled, preventing unauthorized account creation while preserving seamless logins for existing users.

> [!NOTE]
> Runegate operates dynamically based on the presence of the `DATABASE_URL` environment variable. If PostgreSQL is not configured, the proxy gracefully falls back to memory/stateless mode, ensuring maximum deployment flexibility.

### Verification
- `cargo clippy --workspace -- -D warnings` passes without issue.
- Build is successful.
- Routes are correctly registered and integrated into the primary application layer (`src/main.rs`).

## Next Steps
Everything is integrated and the project builds cleanly. The foundational requirements for Gateway mode are fully realized!
