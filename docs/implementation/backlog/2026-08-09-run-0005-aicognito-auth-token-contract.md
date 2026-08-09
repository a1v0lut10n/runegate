# RUN-0005 — AICognito onboarding: auth/token contract design and roadmap

**Status:** In Progress
**Date:** 2026-08-09
**Branch:** `feature/RUN-0005-aicognito-auth-token-contract`

## Premise

Runegate v0.4.0 is released (gateway functionality, magic-link-only
backward compatibility pinned by tests) and runs in production for verbatime.
AICognito — the second fronted service — is at design stage: a Rust git-server
backend whose architecture assigns authentication to Runegate and
authorization to itself, mediated by signed tokens. Its clients (the aicogito
desktop app, git subprocesses, headless machines) cannot use Runegate's
session/redirect model. Runegate has no bearer-token surface today; the
nearest machinery is the upload-ticket RS256 JWT + JWKS endpoint.

The fronting model is decided (see the design record): **Runegate as token
issuer / authorization server; never in AICognito's data path.**

## Scope of RUN-0005

Deliverables of this ticket are the **design record and this roadmap** —
implementation happens under follow-up tickets claimed from `docs/NEXT-TICKET`
per phase. Runegate implementation must not begin before the contract details
below are reviewed and the design record's status is flipped to `accepted`.

## Branching & release discipline

Trunk-based, no long-lived development branch. Each A2–A4 PR merges to
`main` individually, with the token surface **dark by default** (absent/501
without gateway mode + `DATABASE_URL` + issuer config) as an explicit
acceptance criterion, enforced by extending the backward-compat suite.
Releases are tags published deliberately (`v0.5.0` for the token issuer);
deployments pin tags (verbatime's ansible pins `v0.4.0`). A `release/0.x`
maintenance branch is cut from a tag only if a hotfix is ever needed while
`main` carries unreleased work.

## Action items

- **A0 — Fronting-model design record.** Done:
  `docs/design/2026-08-09-aicognito-token-issuer-model.md` (status
  `proposed`, awaiting review).
- **A1 — Pin the token contract details.** Done — the authoritative contract
  now lives in aicognito
  `docs/architecture/runegate-aicognito-auth-token-contract.md` (reviewed
  2026-08-09 from the Runegate v0.4.0 perspective; §5 endpoint surface,
  §5.1 Runegate v1 constraints, §7 claims incl. `typ: at+jwt` and
  `sub` = `users.id` UUID, §7.4 TTLs, §8 refresh rotation, §9 scopes,
  §15 contract tests). Remaining A1 work is only resolving that doc's §16
  open questions 3, 4, and 6.
- **A2 — Runegate: issuer plumbing** (future ticket): signing-key
  management + rotation; generalize `/keys/upload_jwks.json` into an issuer
  JWKS; issuer metadata discovery endpoint.
- **A3 — Runegate: authorization endpoints** (future ticket): authorize
  endpoint (Authorization Code + PKCE) reusing the existing magic-link /
  Google OIDC login surface; token endpoint (code exchange, refresh
  rotation); device-authorization flow. New PostgreSQL tables for codes,
  refresh tokens, and client registrations (gateway mode required).
- **A4 — Contract tests** (future ticket): in-process tests minting and
  validating tokens against the JWKS, PKCE flow end-to-end, refresh
  rotation/revocation, UUID-subject assertions — same style as the v0.4.0
  backward-compat suites; magic-link-only mode must remain unaffected
  (token endpoints 404/501 without gateway mode + DB).
- **A5 — AICognito-side counterparts** (COG tickets, once that repo is
  scaffolded): JWT validation middleware, `aicognito credential` helper,
  login flows — per its architecture doc.
- **A6 — Register the cross-repo contract** in aivolution-meta
  `docs/reference/contracts/` once accepted, and update
  `docs/howto/fronting-a-service.md` with the token-issuer variant as a
  second fronting pattern.

## Verification

- [x] Design record written and linked from this plan.
- [ ] Contract details (A1) reviewed and design record `accepted`.
- [ ] Follow-up runegate tickets claimed for A2–A4.
- [ ] AICognito repo scaffolded with COG prefix; A5 tickets created there.
- [ ] Contract registered in aivolution-meta (A6).
