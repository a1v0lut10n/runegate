# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## What is Runegate

A lightweight Rust identity proxy (actix-web) that fronts internal web apps
with authentication. Two operational modes:

- **Magic-link-only mode** (the published default): passwordless email login
  via time-limited JWT links; in-memory or Redis state; no database required.
- **Gateway mode**: PostgreSQL-backed durable identity with Google OAuth2/OIDC,
  MFA (WebAuthn/TOTP), invite-only onboarding, upload tickets, and a JWKS
  endpoint.

Backward compatibility is a hard constraint: a `.env` from the published
magic-link-only release must keep working unchanged. Gateway-mode features are
opt-in via configuration; nothing may make OIDC/Postgres/Redis settings
required in magic-link-only mode.

Fronted services (see aivolution-meta `repos.yaml`): **verbatime** and
**aicognito**. Onboarding a new fronted service is documented in
`docs/howto/`.

## Build & Development Commands

```bash
cargo build
cargo test                          # unit + integration tests (no external deps)
cargo clippy -- -D warnings
cargo run                           # starts the proxy on RUNEGATE_PORT (default 7870)
scripts/run_integration_tests.sh    # spins up a test target service and exercises the proxy
```

Database-backed tests (`tests/db_integration_tests.rs`) are skipped unless a
test Postgres is configured — see that file's header.

## Branch naming & ticket numbers

This repo's ticket prefix is **`RUN`**, following the workspace-level branch &
ticket conventions (`<type>/RUN-NNNN-short-name` branches, four digits,
zero-padded). `docs/NEXT-TICKET` holds the next free number. To claim it: use
it, and increment the file **in the first commit on the new branch** — normally
the commit that adds your plan doc. Never pick a number by scanning branches or
history. (Branches `RUN-1`..`RUN-4` predate this convention and are unpadded.)

## Documentation & Journaling

The cross-repo documentation workflow is owned by aivolution-meta
(`docs/README.md` there); this repo carries repo-specific additions only.

### docs/ Structure

```
docs/
├── NEXT-TICKET         # Next free RUN ticket number (workspace convention)
├── architecture-overview.md and *.md   # standing design/reference notes
├── howto/              # Operator guides (modes, fronted-service onboarding)
├── implementation/     # Implementation plans
│   ├── backlog/        # Proposed/in-progress specs (RUN-NNNN)
│   └── done/           # Completed specs (moved here after merge)
└── journal/            # Timestamped execution logs
    └── YYYY-MM/        # Monthly folders
```

### Implementation Plans (`docs/implementation/`)

Every non-trivial feature gets a plan in `docs/implementation/backlog/` before
work begins. Format: `YYYY-MM-DD-run-NNNN-short-name.md`.

- **Status** field tracks progress: `Proposed` → `In Progress` → `Done`
- **Sections**: Premise (what exists), numbered action items (A0, A1, ...),
  Verification checklist
- When work is done, update the plan to reflect what was actually implemented
  (not just what was proposed), then move to `done/`

### Journal Entries (`docs/journal/`)

After completing a meaningful unit of work, log a journal entry
(`docs/journal/YYYY-MM/YYYY-MM-DD-short-title.md`) — use the
`/aivolution:journal` skill. Draft and confirm before writing; entries are
immutable once committed.

## Conventions from Aivolution SWE

Generated from Aivolution SWE's conventions (mastermind:
aivolution-mastermind).

- Journal significant events under `docs/journal/`.
- Record decisions as ADRs under `docs/decisions/`.
- Plan non-trivial work under `docs/implementation/`.
- Everything lands reviewably; nothing is written
silently.
