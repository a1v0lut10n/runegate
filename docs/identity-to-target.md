# Identity To Target

When Runegate authenticates a user, the downstream target (your protected app) may need to know who the user is — for example, to associate requests with a per‑user workspace. Runegate supports an identity propagation strategy today via headers, with a JWT‑based method planned.

---

## Headers Mode (Implemented)

- Enable with `RUNEGATE_IDENTITY_HEADERS=true` (default: true).
- For authenticated requests, Runegate injects these headers and strips any client‑supplied versions:
  - `X-Runegate-Authenticated: true|false`
  - `X-Runegate-User: <email>`
  - `X-Forwarded-User: <email>`
  - `X-Forwarded-Email: <email>`
- Target guidance: read `X-Forwarded-User` or `X-Forwarded-Email` to associate a request with a user.
- Security notes:
  - Keep the target internal (e.g., `127.0.0.1:7860` or VPN IP) so only Runegate can reach it.
  - Do not trust identity headers from the public internet; Runegate strips/re‑injects them.

---

## JWT Mode (Planned)

For stronger trust across multiple services (or if you don’t want to trust headers), Runegate can inject a short‑lived JWT signed with a dedicated keypair.

- Request header: `Authorization: Bearer <jwt>` (or a custom header like `X-Runegate-JWT`).
- Claims (example):

```json
{
  "sub": "user@example.com",
  "email": "user@example.com",
  "iat": 1710000000,
  "exp": 1710000600,
  "iss": "runegate",
  "aud": "your-target",
  "sid": "optional-session-id"
}
```

- Recommended algorithms: `RS256` or `EdDSA` (Ed25519). Targets only need the public key.
- Key rotation: include a `kid` header; targets can fetch JWKS or be provisioned with the new public key.
- Planned environment variables (illustrative, subject to change):

```env
# Select identity mode: headers | jwt | none
RUNEGATE_IDENTITY_MODE=jwt

# JWT algorithm: RS256 | EdDSA | HS256
RUNEGATE_DOWNSTREAM_JWT_ALG=RS256

# TTL (seconds) for downstream JWTs
RUNEGATE_DOWNSTREAM_JWT_TTL=600

# Issuer and audience
RUNEGATE_DOWNSTREAM_JWT_ISS=runegate
RUNEGATE_DOWNSTREAM_JWT_AUD=your-target

# Header to carry the token
RUNEGATE_DOWNSTREAM_JWT_HEADER=Authorization
```

If you’re interested in JWT mode, please open an issue with your use case so we can finalize the spec.

---

## Best Practices

- Prefer a dedicated subdomain for Runegate and an internal address for the target.
- Terminate TLS at nginx and set `X-Forwarded-Proto https` so absolute URLs and cookies behave correctly.
- Strip and re‑inject identity headers at the proxy boundary (Runegate already does this) to avoid spoofing.

