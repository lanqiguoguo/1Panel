#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

# The dev server must stay bound to 127.0.0.1 by default.  Pinning VITE_HOST
# to 0.0.0.0 in any env file would expose the unauthenticated dev server to
# the whole network; the only legitimate use is a one-off explicit override
# for remote debugging (flagged by a vite.config.ts warning, not a config).
if grep -lE '^VITE_HOST[[:space:]]*=[[:space:]]*0\.0\.0\.0' "$ROOT_DIR"/frontend/.env* >/dev/null 2>&1; then
    echo "frontend must not pin VITE_HOST to 0.0.0.0 in an env file; keep 127.0.0.1 (override only per-session)" >&2
    exit 1
fi

echo "frontend VITE_HOST stays local check passed"
