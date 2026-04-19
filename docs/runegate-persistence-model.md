# Runegate Persistence Model

## Purpose

This note captures a recommended persistence model for evolving Runegate from a single-instance magic-link gateway into a reusable identity and edge authorization gateway with restart-safe sessions and a path to horizontal scaling.

The recommended direction is:

- **Redis for hot auth state**
- **PostgreSQL for durable identity, policy, and audit data**

This preserves Runegate's current magic-link strengths while making it production-ready for multi-instance cloud deployments.

---

## Architectural Principle

Runegate should separate **current authentication state** from **durable identity truth**.

### Redis should hold hot, short-lived state

Use Redis for state that is:

- frequently read and updated
- naturally time-limited
- shared across instances
- safe to expire automatically

Typical examples:

- active sessions
- magic-link nonce or token state
- MFA challenge state
- rate-limit counters
- short-lived upload tickets
- login flow state such as pre-auth or MFA-required transitions
- short-lived revocation data for downstream tokens

### PostgreSQL should hold durable system-of-record data

Use PostgreSQL for state that is:

- authoritative
- relational
- auditable
- long-lived
- important to preserve independently of session expiry

Typical examples:

- user records
- linked identities
- Google OAuth identities
- magic-link capable email identities
- MFA enrollment metadata
- WebAuthn credential metadata
- TOTP enrollment metadata
- backup code hashes
- invitation records
- domain allowlists and tenant policy
- administrative configuration
- audit logs
- durable issuance history where traceability matters

---

## Why this split is recommended

### Why Redis first

Redis is the best fit for restart-safe auth state because it provides:

- survival across service restarts
- shared state across multiple Runegate instances
- built-in expiry through TTL
- fast reads and writes for per-request auth checks
- simple session revocation and one-time token consumption
- a natural place for distributed rate-limiting

This directly addresses the current limitations of in-memory state, especially:

- sessions disappearing on restart
- rate-limiting resetting on restart
- inability to scale beyond one instance safely

### Why not PostgreSQL for everything

PostgreSQL can store sessions, but it is heavier than necessary for:

- per-request session validation
- one-time magic-link consumption
- MFA step-up challenge state
- rate-limit counters
- high-churn short-lived auth state

Using PostgreSQL for all of this would work, but it would mix cold durable identity data with hot ephemeral auth data and make the gateway more operationally expensive than it needs to be.

### Why not remain fully stateless

A fully stateless design is attractive early on, but it becomes limiting once Runegate needs to support:

- logout everywhere
- session inspection
- session revocation
- one-time-use magic links
- multiple concurrent instances
- challenge-state tracking for MFA
- robust auditability of login flows

For those features, some server-side state becomes the cleaner and more secure approach.

---

## Recommended Session Model

### Cookie contents

The browser cookie should carry only a minimal opaque identifier, for example:

- `session_id`

The cookie should be:

- signed or encrypted
- `Secure`
- `HttpOnly`
- `SameSite=Lax` or stricter depending on the deployment model

### Redis-backed session object

The `session_id` should map to a Redis record containing fields such as:

- `user_id`
- `tenant_id`
- `auth_strength` such as `magic_link`, `google_oauth`, or `mfa`
- `issued_at`
- `last_seen_at`
- `expires_at`
- `csrf_state` or anti-replay metadata where needed
- optional device or client binding hints
- granted scopes or route-level access hints

This keeps the browser lightweight while allowing Runegate to inspect, renew, revoke, or step up sessions centrally.

---

## Recommended Magic-Link Model

Runegate should keep its magic-link functionality, but it should evolve from purely self-contained tokens toward tracked one-time or policy-controlled usage.

### Suggested pattern

- issue a token containing a unique nonce or `jti`
- store token state in Redis with a TTL
- mark the token consumed on successful use
- optionally persist an audit trail in PostgreSQL

### Benefits

This gives Runegate:

- one-time-use semantics
- replay protection
- explicit revocation capability
- visibility into link usage
- a foundation for admin tooling and abuse monitoring

This also leaves room for configurable policies, such as:

- one-time-use links
- limited multi-use links
- short-lived invite links
- support-team or admin-issued links with stricter auditing

---

## MFA and Challenge State

MFA challenge state should also live in Redis.

Examples:

- in-progress WebAuthn challenge
- in-progress TOTP verification step
- pre-auth state waiting for second factor
- short-lived recovery-code validation state

These values are temporary and need to survive process restarts and multi-instance routing, which makes Redis the right location.

The durable metadata for MFA enrollment, however, belongs in PostgreSQL.

Examples:

- registered WebAuthn credentials
- TOTP secret metadata
- recovery code hashes
- enrollment timestamps
- revocation timestamps

---

## Rate Limiting

Rate limiting should move to Redis at the same time as sessions.

Typical counters include:

- magic-link request frequency per email
- login attempts per IP
- login attempts per account
- MFA failures
- upload-ticket issuance frequency
- admin endpoint protection counters

This ensures rate-limits are:

- shared across all Runegate instances
- retained across service restarts
- simple to expire automatically
- suitable for future HA deployments

---

## HA and Deployment Shape

For a production-grade Runegate deployment, the target shape should be:

- multiple Runegate instances behind a load balancer
- Redis as shared auth-state storage
- PostgreSQL as durable identity and audit storage

This allows Runegate to scale horizontally without losing session continuity.

### Operational consequence

Once Redis backs sessions and rate limiting, instance restarts become far less disruptive. Once PostgreSQL backs durable identity data, the gateway gains a true system of record for authentication and policy.

---

## Recommended Three-Phase Evolution

## Phase 1 - Introduce storage abstractions

The first phase should add clear interfaces around state persistence.

Suggested abstractions:

- `SessionStore`
- `LinkStateStore`
- `RateLimitStore`

Optional additional abstractions later:

- `IdentityStore`
- `AuditStore`
- `PolicyStore`
- `UploadTicketStore`

### Initial implementations

Start with:

- `MemorySessionStore`
- `MemoryLinkStateStore`
- `MemoryRateLimitStore`

Then define compatible Redis-backed implementations later without changing the higher-level auth flow.

### Goal of Phase 1

The goal is to decouple Runegate's authentication logic from any one storage backend and make the system testable against both in-memory and shared stores.

---

## Phase 2 - Move hot auth state to Redis

The second phase should introduce Redis-backed implementations for all high-churn ephemeral state.

Move the following to Redis:

- session records
- magic-link token state
- one-time token consumption state
- MFA challenge state
- rate-limit counters
- short-lived upload tickets if Runegate issues them
- pre-auth flow state

### Goal of Phase 2

The goal is to make Runegate restart-safe and multi-instance-safe while preserving existing auth behavior, including magic-link login.

### Result of Phase 2

At the end of this phase, Runegate should be able to:

- survive restarts without dropping sessions
- share auth state across instances
- revoke or inspect sessions centrally
- enforce one-time magic-link semantics
- preserve rate limiting across restarts and instances

---

## Phase 3 - Add PostgreSQL for durable identity, policy, and audit data

The third phase should introduce PostgreSQL as Runegate's durable system of record.

Move or add the following durable domain entities:

- users
- email identities
- OAuth identities
- MFA enrollment metadata
- WebAuthn credential metadata
- TOTP metadata
- backup code hashes
- invitation records
- domain and tenant policy
- administrative configuration
- audit events
- optional durable upload-ticket issuance log

### Goal of Phase 3

The goal is to turn Runegate from a session gateway into a reusable identity and edge authorization platform component.

### Result of Phase 3

At the end of this phase, Runegate should have:

- durable identity records
- policy-driven authentication behavior
- auditability for auth events and admin actions
- a clean separation between transient auth state and durable account data

---

## Suggested Data Ownership Summary

### Redis owns

- current sessions
- current login and MFA flow state
- short-lived token state
- short-lived upload authorization state
- distributed rate limiting

### PostgreSQL owns

- users and linked identities
- MFA enrollment metadata
- policy and invitation state
- audit and compliance records
- long-lived gateway configuration

---

## Practical Next Implementation Step

The best next engineering step is:

1. introduce `SessionStore`, `LinkStateStore`, and `RateLimitStore`
2. keep memory-backed implementations for local development
3. add Redis-backed implementations for production readiness
4. add PostgreSQL later for durable identity, policy, and audit concerns

This lets Runegate keep its current magic-link behavior while evolving in controlled, low-risk increments.

---

## Final Recommendation

The recommended persistence model for Runegate is:

- **Redis as the primary shared store for sessions and other short-lived auth state**
- **PostgreSQL as the durable store for identity, policy, and audit data**

This gives Runegate the right foundation for:

- restart-safe sessions
- horizontal scaling
- durable identity management
- future MFA support
- safer magic-link handling
- reusable edge authorization across multiple applications
