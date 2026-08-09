# Runegate documentation

The shared documentation workflow (taxonomy, mutation patterns, filename
conventions, frontmatter schemas) is owned by **aivolution-meta** —
see `docs/README.md` in that repo. This file carries only runegate-specific
additions.

## Repo-specific layout

- `howto/` — operator guides: [magic-link-only mode](howto/magic-link-only-mode.md),
  [gateway mode](howto/gateway-mode.md), and fronted-service onboarding.
- `implementation/backlog/` → `implementation/done/` — implementation plans
  (`YYYY-MM-DD-run-NNNN-short-name.md`), moved to `done/` after merge.
- `journal/YYYY-MM/` — immutable execution logs.
- Top-level `*.md` files — standing design and reference notes
  (architecture overview, persistence model, lexicon, …).

## Ticket numbers

`NEXT-TICKET` holds the next free `RUN-NNNN` number — claim protocol in the
root `CLAUDE.md`.
