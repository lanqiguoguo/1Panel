#!/usr/bin/env bash
# Checksum contract checks for install.sh (P3-5):
#   - the online download path must refuse to install when the .sha256.txt
#     sidecar is missing or unreadable (fail closed: verify_sha256 exits 1,
#     and fetch_package refuses when the sidecar fetch fails);
#   - the local --pkg path may proceed without a sidecar (the user trusts a
#     file they fetched themselves) but must verify it when one is present.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT

# function-level: verify_sha256 must abort on a missing checksum file
set +e
(
    # shellcheck disable=SC1090
    source "$ROOT_DIR/install.sh" || exit $?
    verify_sha256 "$TEST_ROOT/pkg.tar.gz" "$TEST_ROOT/pkg.tar.gz.sha256.txt"
)
status=$?
set -e
if (( status == 0 )); then
    echo "verify_sha256 must refuse a missing/unreadable checksum file (fail closed)" >&2
    exit 1
fi

# static: the online path must refuse to install when the sidecar cannot be
# fetched, and must run verify_sha256 on the downloaded pair
if ! grep -Fq 'refusing to install an unverified package' "$ROOT_DIR/install.sh"; then
    echo "fetch_package must refuse to install when the checksum sidecar is unavailable" >&2
    exit 1
fi
if ! grep -Fq 'verify_sha256 "$DOWNLOAD_DIR/$file_name" "$DOWNLOAD_DIR/$checksum_name"' "$ROOT_DIR/install.sh"; then
    echo "fetch_package must verify the downloaded package against the sidecar" >&2
    exit 1
fi

# static: the local --pkg path treats the sidecar as optional but verifies it
# when present (no silent skip and no hard fail for local files)
if ! grep -Fq 'no checksum file next to $LOCAL_PKG, skipping sha256 verification' "$ROOT_DIR/install.sh"; then
    echo "load_local_pkg must tolerate a missing sidecar for a local package (warn, not fail)" >&2
    exit 1
fi
if ! grep -Fq 'if [[ -f "$checksum_file" ]]; then' "$ROOT_DIR/install.sh"; then
    echo "load_local_pkg must verify the sidecar when it is present" >&2
    exit 1
fi

echo "installer checksum contract checks passed"
