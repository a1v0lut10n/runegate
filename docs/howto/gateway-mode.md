# Gateway Mode

Runegate can be configured to run in **Gateway Mode** (`RUNEGATE_MODE=gateway`). This is the most feature-rich operational mode, designed to serve as a robust identity-aware proxy for your internal applications. 

## Features
- **Durable Identity**: Uses a PostgreSQL database to persistently store user accounts, identities, and audit logs.
- **Invite-Only Onboarding**: You can restrict sign-ups exclusively to users who have an invite code (`RUNEGATE_SIGNUP_POLICY=invite_only`).
- **OIDC Integration**: Enables users to log in securely via Google OAuth2.
- **Edge Authorization**: Issues short-lived JWT upload tickets (`/upload-ticket`) to grant temporary access to external services (like tusd).
- **MFA (Multi-Factor Authentication)**: Enhances security with WebAuthn or TOTP-based authentication for escalated privileges.

## Configuration Requirements

To run Runegate in Gateway Mode, you must define the following environment variables in your `.env` file or environment:

```env
# Enables Gateway Mode
RUNEGATE_MODE=gateway

# PostgreSQL Connection String (Required for Gateway Mode)
DATABASE_URL=postgres://user:password@localhost/runegate

# Policy to enforce invite codes for new signups
RUNEGATE_SIGNUP_POLICY=invite_only

# Admin API Token for generating/revoking invite codes
RUNEGATE_ADMIN_API_TOKEN=your_secure_admin_token

# Edge Authorization Keys
RUNEGATE_UPLOAD_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n..."
RUNEGATE_UPLOAD_JWKS='{"keys": [{"kty": "RSA", "kid": "...", ...}]}'

# Google OIDC Configuration
RUNEGATE_GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
RUNEGATE_GOOGLE_CLIENT_SECRET=your_google_client_secret
RUNEGATE_GOOGLE_REDIRECT_URL=https://app.example.com/auth/google/callback
```

## Admin Invite API

When `RUNEGATE_SIGNUP_POLICY=invite_only` is set, new users must provide an invite code to sign up. Administrators can generate and manage these codes using the Admin API.

All Admin API requests require the `Authorization: Bearer <RUNEGATE_ADMIN_API_TOKEN>` header.

### Create an Invite Code

```bash
curl -X POST https://app.example.com/admin/invites \
  -H "Authorization: Bearer your_secure_admin_token" \
  -H "Content-Type: application/json" \
  -d '{"max_uses": 1}'
```

### Revoke an Invite Code

```bash
curl -X POST https://app.example.com/admin/invites/123e4567-e89b-12d3-a456-426614174000/revoke \
  -H "Authorization: Bearer your_secure_admin_token"
```

## OIDC Callback Flow

When Gateway mode is enabled alongside OIDC, Runegate automatically enforces the signup policy during the OIDC callback. If the policy is `invite_only`, new Google users will be denied access and instructed to create an account first using an invite code via the primary login screen. Existing users will be authenticated normally.
