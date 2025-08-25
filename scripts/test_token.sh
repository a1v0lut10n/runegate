#!/usr/bin/env bash
# Quick token generation script (relative to repo root)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Load .env if present (export all vars during sourcing)
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

EMAIL="${1:-test@example.com}"
ACTION="${2:-create}"

cargo run --example test_jwt_validation "${EMAIL}" "${ACTION}"
