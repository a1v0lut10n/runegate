# Runegate Consolidated Migration Strategy and Implementation Plan

## Purpose

This document consolidates the earlier Runegate change requests with the later architectural refinements into a single migration strategy and implementation plan.

It preserves the intent of the existing change requests:

- keep Runegate backward compatible
- preserve the existing magic-link functionality
- evolve Runegate into a reusable identity and edge authorization gateway
- support Google sign-in, MFA, upload tickets, and invite-only onboarding
- keep UI hosting decoupled from the auth runtime

It also adopts the revised internal architecture:

- **Redis becomes the primary shared store for active sessions and other hot auth state**
- **PostgreSQL becomes the durable system of record for identity, policy, and audit data**
- **Runegate remains the single authentication authority**
- **Upstream applications continue to trust Runegate-injected identity headers**

This plan is intended to replace the need for a separate gap analysis.

---

## Executive Summary

Runegate should evolve in a controlled, backward-compatible sequence from a single-instance magic-link gateway into a production-grade identity and edge authorization gateway.

The high-level target state is:

- preserve `magic-link-only` mode as a first-class supported mode
- add a new `gateway` mode for richer authentication flows
- continue to host configurable static authentication UI
- support Google OAuth and mandatory MFA in gateway mode
- support invite-only onboarding policy without user enumeration
- support upload-ticket issuance as an edge authorization capability
- make sessions restart-safe and multi-instance-safe
- separate ephemeral auth state from durable identity and policy data

The most important internal refinement in this consolidated plan is:

- **do not make PostgreSQL the primary store for active sessions**
- instead use **Redis for active sessions, challenge state, token-use state, and rate limiting**
- reserve **PostgreSQL for durable domain entities**

---

## Architectural Direction

## Runegate's role

Runegate should be treated as:

- the authentication authority
- the session authority
- the host for authentication UI assets
- the injector of trusted identity headers
- an edge authorization broker for upload tickets where needed

Runegate should not become:

- the main business logic service
- a general application BFF
- a pipeline orchestration component
- an all-purpose policy engine for unrelated application domains

## Upstream contract

Applications behind Runegate should continue to trust:

- `X-User-*` style injected identity headers
- a valid session established by Runegate
- optional upload-ticket contracts exposed by Runegate in gateway mode

Applications should not duplicate:

- credential storage
- password or magic-link logic
- MFA enrollment secrets
- identity-provider orchestration

---

## Guiding Principles

1. **Backward compatibility first**  
   Existing deployments must continue to work with `magic-link-only` mode as the default or explicitly supported legacy mode.

2. **Feature growth without architectural confusion**  
   New features should not force Runegate to absorb application-specific concerns.

3. **Hot state and durable state must be separated**  
   Redis should hold high-churn ephemeral state. PostgreSQL should hold durable identity, policy, and audit records.

4. **No user enumeration**  
   Public flows must continue to use uniform responses and jitter where appropriate.

5. **Cloud-ready but not cloud-locked**  
   The architecture should work on-prem or in cloud deployments without changing the core gateway contract.

6. **Static auth UI remains configurable**  
   Authentication UI assets must continue to be hostable from disk or CDN, with clean contracts for branding and configuration injection.

---

## Target Functional Scope

The target product scope for Runegate should include:

- `magic-link-only` mode
- `gateway` mode
- hardened magic links
- Google OAuth sign-in
- mandatory MFA in gateway mode
- WebAuthn as the preferred MFA method
- TOTP as a fallback MFA method
- backup codes
- upload-ticket issuance support
- invite-only signup policy
- optional future domain-allowlist signup policy
- configurable authentication UI hosting
- shared session storage
- centralized rate limiting
- durable identity and audit storage

---

## Operating Modes

## Mode 1 - `magic-link-only`

This preserves the current behavior:

- email entry
- magic-link delivery
- session establishment after link consumption
- no Google sign-in requirement
- no MFA requirement
- no new gateway-only features forced on deployments

All richer features must remain no-ops in this mode.

## Mode 2 - `gateway`

This enables the new model:

- identifier-first UX
- magic-link fallback
- Google sign-in
- PREAUTH to SESSION progression
- mandatory MFA on first login
- upload-ticket support
- invite-only or future policy-gated onboarding
- trusted identity-header injection to upstream applications

---

## Consolidated Internal Persistence Model

## Redis - primary shared auth-state store

Redis should own the high-churn, short-lived, multi-instance-sensitive state:

- active sessions
- PREAUTH state
- magic-link token state
- token-consumption state
- JTI or nonce replay prevention
- device-binding state
- MFA challenge state
- TOTP verification state
- WebAuthn challenge state
- distributed rate limits
- short-lived invite flow state
- short-lived upload-ticket state if applicable
- temporary OAuth state such as nonce and PKCE verifier
- optional short-lived token revocation state

### Why Redis owns this layer

Redis is the right fit because this state is:

- short-lived
- frequently read and updated
- naturally TTL-driven
- operationally easier to share across multiple gateway instances
- well suited to revocation and one-time-use semantics
- better aligned with restart safety than in-memory storage
- lighter than PostgreSQL for high-frequency auth-path reads and writes

## PostgreSQL - durable identity, policy, and audit store

PostgreSQL should own the long-lived and relational domain entities:

- users
- linked email identities
- linked Google identities
- MFA enrollment metadata
- WebAuthn credential metadata
- TOTP metadata
- backup code hashes
- invitations
- invite usage records
- domain and signup policy records where persisted
- administrative configuration
- audit events
- durable upload-ticket issuance logs if desired
- other future gateway-level policy objects

### Why PostgreSQL owns this layer

PostgreSQL is the right fit because this state is:

- authoritative
- relational
- auditable
- long-lived
- important to preserve independently of session expiry

## Explicit refinement to earlier plans

Where earlier proposals allowed sessions to live in PostgreSQL or remain fully stateless, this consolidated strategy refines that design:

- **active sessions should primarily live in Redis**
- PostgreSQL should not be the primary session validation path
- PostgreSQL may retain durable audit information about session creation or revocation, but not serve as the main hot-path session store

This is the most important internal reframing in the consolidated plan.

---

## Consolidated Session Model

## Session stages

The staged session model from the earlier change request should be retained and formalized:

- unauthenticated
- identification initiated
- PREAUTH
- MFA challenge or enrollment
- full SESSION

This is a strong design and should remain part of the target architecture.

## Cookie model

Cookies should carry minimal opaque identifiers rather than large self-contained session payloads.

Examples:

- `preauth_id`
- `session_id`
- optional device-binding cookie
- optional invite cookie
- CSRF or anti-replay tokens as needed

Cookies should be:

- `Secure`
- `HttpOnly` where applicable
- `SameSite=Lax` or stricter depending on deployment context
- signed or encrypted as needed

## Redis-backed session records

The `session_id` and `preauth_id` should map to Redis records containing fields such as:

- user identifier
- tenant or scope identifier if needed
- authentication method
- authentication strength
- issued time
- last seen time
- expiry time
- MFA completion state
- anti-replay metadata
- optional device-binding metadata
- scopes or route-access hints if Runegate needs them

This gives Runegate central control over:

- renewal
- inspection
- revocation
- step-up auth transitions
- multi-instance continuity

---

## Consolidated Magic-Link Strategy

Runegate should preserve its existing magic-link capability, but harden it and move validity state into Redis.

## Recommended approach

- issue short-lived magic links
- embed a `jti` or equivalent unique identifier
- persist token state in Redis with TTL
- enforce one-time-use by marking successful consumption
- retain device-binding where configured
- optionally persist durable issuance and consumption audit records in PostgreSQL

## Why this is the preferred refinement

This preserves the existing strength of passwordless access while enabling:

- single-use semantics
- replay protection
- operational revocation
- restart-safe verification
- multi-instance deployments
- traceability where required

---

## Consolidated Google Sign-In Strategy

Google sign-in should remain part of `gateway` mode.

The preferred flow remains:

- start authorization with PKCE
- handle callback server-side
- establish PREAUTH on success
- continue through MFA
- rotate to full SESSION after successful MFA

The temporary OAuth flow state should live in Redis:

- nonce
- state
- PKCE verifier
- flow correlation identifiers

Any durable identity linkage created by Google sign-in should live in PostgreSQL.

---

## Consolidated MFA Strategy

The MFA direction from the earlier change request should be retained.

## MFA requirements in gateway mode

- mandatory on first successful login
- WebAuthn preferred
- TOTP fallback
- backup codes supported

## State placement

### Redis should own

- in-progress WebAuthn challenge state
- in-progress TOTP verification state
- temporary MFA step-up flow state
- recovery verification flow state

### PostgreSQL should own

- WebAuthn credential metadata
- TOTP enrollment metadata
- backup code hashes
- enrollment timestamps
- revocation timestamps
- MFA-related audit records

This preserves the product behavior while clarifying persistence boundaries.

---

## Consolidated Invite-Only Strategy

The invite-only change request should be adopted as a first-class policy feature.

## Signup policy model

Retain:

- `open`
- `invite_only`
- optional future `domain_allowlist`

Default remains:

- `open`

This preserves current behavior until explicitly changed.

## Invite durability

Invites and invite usage records should remain durable PostgreSQL entities.

Suggested durable records include:

- invite master record
- invite scope
- expiration
- maximum uses
- current usage count
- creation and revocation metadata
- invite usage audit log

## Invite flow state

Short-lived invite acceptance state should live in Redis or cookies as needed:

- invite-applied banner state
- invite validation context
- short-lived invite flow continuation

## Invite policy behavior

The invite-only behavior from the earlier CR should be retained:

- existing users continue unaffected
- new user creation requires a valid invite
- magic-link and Google-based first login both respect invite policy
- public responses remain uniform to avoid enumeration

This is already a strong design and needs little conceptual change.

---

## Consolidated Upload-Ticket Strategy

The earlier dual-model upload-ticket design should be retained.

Runegate should support two issuance patterns:

- **app-minted**
- **Runegate-minted**

This is preferable to forcing only one pattern because it preserves flexibility for different deployments.

## App-minted pattern

- upstream application receives trusted identity headers from Runegate
- application BFF mints the upload ticket

## Runegate-minted pattern

- Runegate exposes a dedicated endpoint such as `POST /upload-ticket`
- Runegate mints a short-lived upload authorization token

## Persistence guidance

Short-lived ticket validity state or replay state may live in Redis if needed. Durable issuance logging may live in PostgreSQL if auditability matters.

---

## UI Hosting and Front-End Contract

The earlier UI decoupling requirement should be retained in full.

Runegate should continue to support authentication UI served from:

- configurable on-disk asset directory
- configurable external asset URL or CDN

Runegate should remain able to host assets for routes such as:

- `/auth/login`
- `/auth/register`
- `/mfa`
- optional invite landing and invite-required screens

Applications such as Verbatime may continue to build and supply these assets separately from Runegate's runtime.

This separation is important and should not be collapsed.

---

## Security and Abuse-Resistance Requirements

The consolidated plan should preserve and strengthen the earlier security design.

Key requirements:

- no user enumeration
- uniform responses on identify and invite-sensitive paths
- jitter where useful
- rate limits per IP and per account or email
- device binding for magic-link flows where enabled
- one-time-use token enforcement
- auditable admin actions
- auditable invite creation, usage, and revocation
- strong cookie settings
- strict upstream trust boundaries for injected identity headers

These concerns become even more important as Runegate becomes a reusable gateway product.

---

## Recommended Interface Abstractions

Before new storage backends are added, Runegate should introduce explicit interfaces around state ownership.

## Phase-one abstraction set

Introduce abstractions such as:

- `SessionStore`
- `PreauthStore`
- `LinkStateStore`
- `RateLimitStore`
- `ChallengeStore`

Optionally add:

- `InviteStore`
- `IdentityStore`
- `AuditStore`
- `PolicyStore`
- `UploadTicketStore`

## Initial implementations

Start with memory-backed implementations for local development and current deployments:

- `MemorySessionStore`
- `MemoryPreauthStore`
- `MemoryLinkStateStore`
- `MemoryRateLimitStore`
- `MemoryChallengeStore`

These should preserve existing behavior while allowing future migration underneath stable auth logic.

---

## Consolidated Migration Phases

## Phase 1 - Introduce mode boundaries and storage abstractions

### Objectives

- preserve current behavior
- formalize `magic-link-only` and `gateway` modes
- introduce explicit storage interfaces
- keep UI hosting configurable
- avoid changing user-visible behavior more than necessary

### Deliverables

- `RUNEGATE_MODE`
- clear internal separation between legacy and gateway paths
- storage traits for session, preauth, link state, rate limit, and challenge state
- memory-backed implementations for all stores
- no-op behavior for gateway-only features in `magic-link-only` mode
- stable asset hosting contract for login/register/MFA screens

### Outcome

At the end of this phase, Runegate remains operationally similar to today, but the internals are prepared for evolution.

---

## Phase 2 - Move hot auth state to Redis

### Objectives

- make sessions restart-safe
- make gateway flows multi-instance-safe
- eliminate dependence on single-process memory for critical auth state
- preserve backward compatibility

### Deliverables

Redis-backed implementations for:

- sessions
- PREAUTH
- magic-link state
- one-time token consumption
- device-binding state
- OAuth flow state
- MFA challenge state
- rate limiting
- short-lived invite flow state
- optional short-lived upload-ticket state

### Outcome

At the end of this phase, Runegate can:

- survive restarts without dropping active sessions
- share auth state across instances
- revoke sessions centrally
- enforce one-time token semantics robustly
- preserve rate limits across restarts and scale-out

This is the key production-readiness milestone.

---

## Phase 3 - Implement gateway-mode auth features

### Objectives

- activate the feature set envisioned in the earlier change request
- preserve the legacy mode
- keep persistence boundaries clean

### Deliverables

- identifier-first flow in gateway mode
- hardened magic-link flow
- PREAUTH to SESSION progression
- Google OAuth sign-in with Redis-backed temporary flow state
- WebAuthn enrollment and challenge
- TOTP fallback
- backup code generation and storage
- full session rotation after MFA
- upload-ticket support
- trusted identity-header injection to upstream app

### Persistence requirements

- Redis remains the hot-path state store
- PostgreSQL begins to own durable identity and MFA records where needed

### Outcome

At the end of this phase, Runegate functions as a real gateway product component in single-app deployments.

---

## Phase 4 - Add durable identity, invite, policy, and audit storage in PostgreSQL

### Objectives

- establish Runegate as a durable identity and policy system of record
- add invite-only onboarding and auditability
- preserve compatibility with open signup

### Deliverables

PostgreSQL-backed domain entities for:

- users
- email identities
- Google identities
- MFA enrollment metadata
- backup code hashes
- invites
- invite usages
- audit logs
- administrative configuration
- optional policy tables

Feature deliverables:

- `RUNEGATE_SIGNUP_POLICY`
- `open` and `invite_only`
- optional future `domain_allowlist`
- admin invite APIs
- invite landing flow
- durable invite audit
- admin audit events

### Outcome

At the end of this phase, Runegate has durable policy and identity data and supports invite-only onboarding in a clean, reusable way.

---

## Phase 5 - Hardening, HA, and productization

### Objectives

- make Runegate operationally solid as a reusable open-source gateway
- prepare for multi-instance and cloud deployment
- reduce single-point-of-failure assumptions

### Deliverables

- multiple Runegate instances behind a load balancer
- Redis in shared production configuration
- PostgreSQL backups and migration discipline
- structured logs
- health checks
- metrics
- operational runbooks
- deployment examples for on-prem and cloud
- documentation for asset delivery, branding injection, and admin APIs
- compatibility notes for magic-link-only users upgrading to gateway mode

### Outcome

At the end of this phase, Runegate is not just feature-rich but operationally credible as an edge identity component.

---

## Recommended Feature Sequence Within the Phases

A practical implementation order that respects both the old CRs and the refined internals is:

1. introduce mode split and storage abstractions
2. add Redis-backed stores
3. harden magic-link flow
4. add PREAUTH to SESSION model
5. add Google sign-in
6. add MFA enrollment and challenge flows
7. add backup codes
8. add upload-ticket capability
9. add PostgreSQL-backed durable identity model
10. add invite-only onboarding and admin APIs
11. add hardening and HA features

This sequencing gives you the user-visible product evolution you wanted while reducing technical debt rather than increasing it.

---

## Data Ownership Summary

## Redis owns

- active sessions
- PREAUTH state
- challenge state
- short-lived OAuth flow state
- magic-link token-use state
- device binding state
- distributed rate limiting
- short-lived invite flow state
- optional short-lived upload-ticket state

## PostgreSQL owns

- users
- linked identities
- MFA enrollment metadata
- backup code hashes
- invites and invite usages
- signup policy and durable configuration
- audit logs
- durable admin and issuance records

This summary should guide implementation decisions whenever ownership is ambiguous.

---

## What This Consolidated Plan Changes From the Earlier CRs

This plan intentionally preserves the earlier feature and product direction. The main changes are internal clarifications:

1. **Sessions are no longer primarily modeled as a PostgreSQL concern**  
   They should live in Redis.

2. **Magic-link validity should be enforced in Redis, not only in durable tables**  
   Durable audit can still live in PostgreSQL.

3. **Storage abstractions should be introduced before feature expansion grows too large**  
   This reduces risk and keeps the gateway maintainable.

4. **Invite-only remains valid and should be adopted**  
   It simply sits more clearly on top of the revised Redis/PostgreSQL split.

These refinements strengthen the earlier plans without changing their product intent.

---

## Final Recommendation

Runegate should proceed as a backward-compatible migration from a single-instance magic-link service into a reusable identity and edge authorization gateway.

The recommended foundation is:

- **Redis for active sessions and other short-lived auth state**
- **PostgreSQL for durable identity, policy, and audit data**
- **retention of `magic-link-only` mode**
- **feature growth in `gateway` mode**
- **invite-only onboarding as a durable policy feature**
- **upload-ticket issuance as an edge authorization capability**
- **continued decoupling of auth UI from runtime logic**

This consolidated plan preserves the best parts of the earlier change requests while adopting the architectural refinements needed for restart safety, horizontal scaling, and long-term product reuse.
