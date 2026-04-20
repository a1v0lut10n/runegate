# Runegate Auth & Upload Lexicon

**Date:** 2025-09-20  
**Scope:** Acronyms and concepts used across Runegate, auth, MFA, OIDC, and uploads.

> Tip: Entries are alphabetical. Many include “Why it matters” and “Gotchas”.

---

## A

### ACR / Authentication Context Class Reference
**What:** A string (or set) expressing the *assurance level* of an authentication (e.g., “urn:mace:incommon:iap:silver”).  
**Why it matters:** Lets apps demand stronger auth for sensitive actions.  
**Gotchas:** Often confused with **AMR**; *ACR* is about *level*, not specific methods.

### AMR / Authentication Methods Reference
**What:** A list of the methods used in this login (e.g., `["pwd","otp","webauthn","email"]`).  
**Why it matters:** Downstream services can require or record that MFA happened.  
**In Runegate:** We include this in the session (header `X-User-AMR` or in a JWT).

### Auth Code Flow (OAuth 2.0)
**What:** Browser gets an authorization code, backend exchanges it for tokens.  
**Why it matters:** Keeps tokens off the browser; use with **PKCE**.  
**Gotchas:** Don’t use implicit flow on the web.

---

## B

### BFF / Backend For Frontend
**What:** Server-side app that talks to APIs on behalf of the browser.  
**Why it matters:** Keeps secrets/tokens off the client; ideal for OIDC code+PKCE.  
**In our stack:** The app BFF can also mint **upload tickets**.

---

## C

### CSP / Content Security Policy
**What:** HTTP header restricting where scripts, styles, etc. can load from.  
**Why it matters:** Major defense against XSS.  
**Gotchas:** If hosting login UI on a CDN, add that origin to `script-src`.

### CSRF / Cross-Site Request Forgery
**What:** An attack that tricks a browser into sending authenticated requests.  
**Why it matters:** All state-changing POSTs should require an anti-CSRF mechanism.  
**Mitigations:** SameSite cookies, Origin checks, double-submit tokens.

### CORS / Cross-Origin Resource Sharing
**What:** Browser policy controlling cross-origin requests.  
**Why it matters:** Needed when Uppy talks to **tusd** on a different domain.  
**Gotchas:** Preflights must include correct `Access-Control-Allow-*` headers.

---

## D

### Device Binding (for magic links)
**What:** Tying a sign-in link to the device that requested it (via a short-lived cookie).  
**Why it matters:** Prevents link forwarding/phishing abuse.  
**Gotchas:** Provide an alternate on-screen code if the cookie is missing.

---

## F

### FedCM / Federated Credential Management
**What:** Browser-mediated identity API replacing third-party cookies/iframes for federated login UX.  
**Why it matters:** Google/GIS is moving to FedCM for web SSO.  
**Gotchas:** Frontend UX changes; backend OIDC code flow remains the same.

---

## G

### GCS / Google Cloud Storage
**What:** Object storage in GCP used for media and transcripts.  
**Why it matters:** Pairs with **tusd** via the GCS store for resumable uploads.

### GIS / Google Identity Services
**What:** Google’s JS SDK for sign-in; now integrates with **FedCM**.  
**Why it matters:** Frontend UX for “Sign in with Google”.

---

## I

### IdP / Identity Provider
**What:** Service that authenticates users and issues identity tokens (e.g., Google, Runegate-in-IdP-mode).  
**Why it matters:** Central source of truth for authentication.

### Implicit Flow (OAuth 2.0)
**What:** Returns tokens directly in the browser redirect.  
**Why it matters:** **Do not use on the web**; use **Auth Code + PKCE** instead.

---

## J

### JTI / JWT ID
**What:** Unique identifier for a token.  
**Why it matters:** Enables single-use tokens and replay protection (e.g., magic links, upload tickets).  
**Gotchas:** Store processed JTIs (e.g., in Redis) to enforce one-time use.

### JWT / JSON Web Token
**What:** Signed (optionally encrypted) token conveying claims.  
**Why it matters:** Used for sessions, upload tickets, and inter-service identity.  
**Gotchas:** Validate signature, `iss`, `aud`, `exp`, and clock skew; rotate keys.

### JWKS / JSON Web Key Set
**What:** JSON document listing public keys for verifying JWTs.  
**Why it matters:** Lets services verify tokens minted by another service (e.g., Runegate → tusd).  
**Gotchas:** Manage key rotation via `kid`.

---

## M

### Magic Link (passwordless)
**What:** Single-use sign-in link emailed to a user.  
**Why it matters:** Great UX; no passwords to store.  
**Hardening:** Short TTL, device-binding, one-time JTI, allowlist `return_to`.

### MFA / Multi-Factor Authentication
**What:** Requiring ≥2 independent factors (something you have/are/know).  
**Why it matters:** Stops most account takeovers.  
**In our plan:** **WebAuthn** preferred; **TOTP** fallback; backup codes for recovery.

---

## N

### Nonce
**What:** Unique value used once to prevent replay.  
**Why it matters:** In OIDC, bind ID tokens to a specific auth request; in WebAuthn, part of the challenge.

---

## O

### OAuth 2.0
**What:** Authorization framework underlying OIDC and many API auth flows.  
**Why it matters:** Provides scopes, tokens, and standardized exchanges.

### OIDC / OpenID Connect
**What:** Identity layer on top of OAuth 2.0 (ID tokens, user info).  
**Why it matters:** Standard way for apps to authenticate users via an IdP.  
**Gotchas:** Always use **Auth Code + PKCE** for web clients.

---

## P

### Passkey
**What:** User-friendly name for WebAuthn credentials synced across devices.  
**Why it matters:** Phishing-resistant; replaces passwords.

### PKCE / Proof Key for Code Exchange
**What:** Mechanism to bind the OAuth authorization code to the client using a code challenge/verifier.  
**Why it matters:** Prevents interception of the code (especially for public clients).  
**Gotchas:** Store `code_verifier` server-side until token exchange.

### PREAUTH Cookie
**What:** Short-lived cookie marking that the **primary factor** passed, but MFA not yet completed.  
**Why it matters:** Lets us redirect to `/mfa` safely before issuing a full session.  
**TTL:** ~10–15 minutes.

---

## R

### RP ID / Relying Party ID (WebAuthn)
**What:** Domain scope for WebAuthn (e.g., `id.example.com`).  
**Why it matters:** Credentials are bound to the RP ID; must match during verification.

---

## S

### SameSite (cookie attribute)
**What:** Controls cross-site cookie sending.  
**Why it matters:** `SameSite=Lax` is a good default for auth cookies.

### SCA / Strong Customer Authentication
**What:** PSD2 requirement (EU) for multi-factor payment authentication.  
**Why it matters:** Stripe Checkout handles this as needed—no extra app logic.

### SESSION Cookie
**What:** Full, long(er)-lived cookie issued after MFA completion.  
**Why it matters:** Required to pass Runegate’s proxy gate to the upstream app.

### SSO / Single Sign-On
**What:** One login used across multiple apps (usually via OIDC/SAML).  
**Why it matters:** Reduces friction; centralizes auth policies.

---

## T

### TOTP / Time-based One-Time Password
**What:** 6-digit rotating codes generated from a shared secret and time.  
**Why it matters:** Widely supported MFA fallback.  
**Gotchas:** Store secrets encrypted/peppered; rate-limit attempts; verify with small time window.

### tus / Resumable Upload Protocol
**What:** Open protocol for resumable, repairable uploads.  
**Why it matters:** Powers Uppy + tusd → GCS without custom chunk logic.

### tusd
**What:** Reference server for the tus protocol.  
**Why it matters:** Provides hooks, persistence, and GCS store for streaming uploads.

---

## U

### Uppy
**What:** Client-side JavaScript file uploader with plugins (Tus, Dashboard).  
**Why it matters:** Handles retries, resume, and metadata; great UX for large files.

### UV / User Verification (WebAuthn)
**What:** Whether the authenticator verified the user (e.g., via biometrics/PIN).  
**Why it matters:** Enforce `userVerification="required"` for stronger guarantees.

### Upload Ticket (JWT)
**What:** Short-lived signed JWT granting permission to upload (claims: user, project, size/mime limits).  
**Why it matters:** Keeps Runegate out of the data path while enforcing policy at tusd hooks.

---

## W

### WebAuthn
**What:** W3C standard for public-key-based, phishing-resistant authentication.  
**Why it matters:** Preferred factor for MFA and passwordless sign-in.  
**Gotchas:** Set RP ID/origins correctly; support multiple credentials; handle UV requirements.

---

## X

### X-User-AMR (header)
**What:** Header injected by Runegate to upstream indicating the methods used (e.g., `["email","webauthn"]`).  
**Why it matters:** Upstream can enforce step-up for sensitive actions.

---

## Z

### Zero Trust (honorable mention)
**What:** Principle of authenticating and authorizing *every* request, not trusting the network alone.  
**Why it matters:** Runegate embodies this at the edge; upstream apps check headers or JWT claims each time.

---

## Related Concepts (Quick Hits)

- **Backup Codes:** One-time codes for account recovery; store hashed; show once.  
- **BBR:** Modern TCP congestion control; can help throughput on high-BDP links.  
- **Behind-Proxy (tusd):** Setting to ensure correct `Location`/offsets when tusd sits behind a proxy.  
- **Signed URLs (GCS):** Time-limited URLs for download playback; keep Runegate out of egress path.  
- **Return-To Allowlist:** Limits post-auth redirects to trusted paths/domains.

---

### Change Log
- v1.0 (2025-09-20): Initial version.
