# Magic-Link-Only Mode

Runegate can be configured to run in **Magic-Link-Only Mode** (`RUNEGATE_MODE=magic-link-only`). This is a lightweight, stateless operational mode that is perfect for simple deployments where a full database is not desired.

## Features
- **Stateless Authentication**: Fully relies on in-memory or Redis-backed session stores and JWT verification. For distributed deployments behind a load balancer, setting `REDIS_URL` will automatically configure a robust, shared session store.
- **Zero Database Requirements**: Does not require a PostgreSQL instance.
- **Easy Deployment**: Requires very few configuration variables.
- **Email-Based Magic Links**: Users authenticate via magic links sent directly to their email address. 

## Configuration Requirements

To run Runegate in Magic-Link-Only Mode, use the following configuration in your `.env` file:

```env
# Enables Magic-Link-Only Mode (This is the default if unspecified)
RUNEGATE_MODE=magic-link-only

# Required: JWT secret for token signing
RUNEGATE_JWT_SECRET=your_very_secure_random_string_for_jwt_at_least_32_bytes

# Required: Session key for cookie encryption
RUNEGATE_SESSION_KEY=your_very_secure_random_string_for_session_cookies_at_least_64_bytes

# Optional: Redis connection string for distributed session management
# If omitted, Runegate defaults to an in-memory session store.
# REDIS_URL=redis://127.0.0.1:6379

# Required: Email configuration must be provided in config/email.toml
```

## Limitations

Because this mode does not utilize a persistent database, it lacks the following capabilities:
- **Durable Identity**: No long-term storage of user identities or audit logs.
- **Invite-Only Policies**: `RUNEGATE_SIGNUP_POLICY=invite_only` will not function as it requires a database to track and consume invites.
- **Google OIDC integration**: While you can technically enable OIDC, there is no persistent backend to securely tie external identities to local ones. 
- **Edge Authorization**: Upload tickets (`/upload-ticket`) and keys are disabled. 

For full-featured operations, please consider migrating to [Gateway Mode](./gateway-mode.md).
