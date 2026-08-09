# AICognito Token-Issuer Model Accepted

**Date**: 2026-08-09
**Time**: 16:36:35
**Status**: Completed

## Summary

Adopted the fronting model for Runegate's second consumer: for AICognito,
Runegate acts as an OAuth2/OIDC-style authorization server — auth pages,
PKCE and device flows, token endpoint, issuer JWKS — and stays entirely out
of AICognito's git data path. The design record is accepted and the
authoritative token contract is pinned in AICognito's architecture set.

## Context

AICognito (the planned Rust git-server backend hosting aicogito minds) needs
authentication, but its clients are git subprocesses and desktop/CLI apps
that cannot follow Runegate's session/redirect model. Its architecture
assigns authentication to Runegate and authorization to itself, mediated by
signed tokens. Verbatime's proxy-style integration — Runegate's first — does
not fit: git Smart HTTP must stream unbuffered, AICognito is role-split
rather than single-target, and the architecture forbids email as an
authorization key.

## Details

The decision (design record `2026-08-09-aicognito-token-issuer-model.md`,
claimed under RUN-0005): AICognito validates Runegate-issued RS256 `at+jwt`
access tokens locally against Runegate's JWKS, keyed on `(iss, sub)` with
`sub` = Runegate's `users.id` UUID; scopes are coarse capability ceilings;
refresh tokens are opaque, rotating, and family-revoked. Alternatives
(full proxy, hybrid, direct-to-Google) were weighed and rejected.

The contract doc lives in AICognito's architecture set
(`runegate-aicognito-auth-token-contract.md`, AICognito PR #1) and was
reviewed against the Runegate v0.4.0 implementation. The review surfaced the
v1 constraints now recorded in its §5.1: the token surface requires gateway
mode + PostgreSQL (dark by default elsewhere), `/oauth/authorize` needs
login-flow continuation (magic-link consume currently redirects to a fixed
default), issuer signing keys must be separate from the upload-ticket keys,
device flow needs a verification page in the auth UI, token endpoints need
rate limiting, and no token/code logging.

Process decisions alongside: trunk-based development (no long-lived dev
branch) with dark-by-default as a per-PR acceptance criterion; releases from
tags (v0.4.0 published to crates.io earlier today); deployments pin tags
(verbatime's ansible now pins v0.4.0). Implementation proceeds under
follow-up tickets per the RUN-0005 roadmap (issuer plumbing → authorization
endpoints → contract tests → AICognito counterparts).

## Links

- Design record: `docs/design/2026-08-09-aicognito-token-issuer-model.md`
- Roadmap: `docs/implementation/backlog/2026-08-09-run-0005-aicognito-auth-token-contract.md`
- Contract: aicognito `docs/architecture/runegate-aicognito-auth-token-contract.md` (aicognito PR #1)
- Onboarding guide: `docs/howto/fronting-a-service.md`
- PR: https://github.com/a1v0lut10n/runegate/pull/35
