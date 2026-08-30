#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

if grep -Fq '/tmp/get-docker.sh' "$ROOT_DIR/install.sh"; then
    echo "installer must not use a predictable docker script path" >&2
    exit 1
fi

TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
BIN_DIR="$TEST_ROOT/bin"
mkdir -p "$BIN_DIR"

# Keep the command lookup environment minimal so a host Docker installation
# cannot cause install_docker to skip its download path.  sh resolves through
# PATH (install.sh calls `env -u PANEL_PASSWORD sh ...`), so it must be the
# recording stub below; env is required by that same invocation.
for tool in mktemp chmod rm tee date env; do
    ln -s "$(command -v "$tool")" "$BIN_DIR/$tool"
done

cat > "$BIN_DIR/curl" <<'CURL_STUB'
#!/bin/bash
set -euo pipefail

output=""
while (($#)); do
    if [[ "$1" == "-o" ]]; then
        output=$2
        shift 2
    else
        shift
    fi
done
[[ -n "$output" ]]
printf '%s\n' "$output" > "$TEST_ROOT/curl-output"
{
    printf '%s\n' '#!/bin/sh'
    printf '%s\n' "printf '%s\\n' docker-script-ran > '$TEST_ROOT/script-ran'"
    printf '%s\n' "printf '%s\\n' '#!/bin/sh' 'exit 0' > '$BIN_DIR/docker'"
    printf '%s\n' "chmod 755 '$BIN_DIR/docker'"
} > "$output"
printf '%s\n' "$(/usr/bin/stat -c '%a' "${output%/*}")" > "$TEST_ROOT/curl-dir-mode"
printf '%s\n' "$(/usr/bin/stat -c '%a' "$output")" > "$TEST_ROOT/curl-file-mode"
CURL_STUB
chmod 755 "$BIN_DIR/curl"

cat > "$BIN_DIR/sh.stub" <<'SH_STUB'
#!/bin/bash
set -euo pipefail

script_path=${1:?missing script path}
printf '%s\n' "$script_path" > "$TEST_ROOT/sh-argument"
printf '%s\n' "$(/usr/bin/stat -c '%a' "${script_path%/*}")" > "$TEST_ROOT/sh-dir-mode"
printf '%s\n' "$(/usr/bin/stat -c '%a' "$script_path")" > "$TEST_ROOT/sh-file-mode"
# record whether PANEL_PASSWORD reached the spawn, then run the script for real
printf '%s\n' "$(env | /usr/bin/grep -c '^PANEL_PASSWORD=' || true)" > "$TEST_ROOT/sh-env-password-count"
exec /bin/sh "$@"
SH_STUB
chmod 755 "$BIN_DIR/sh.stub"
# sh must be the recording stub; a symlink keeps `env -u PANEL_PASSWORD sh`
# resolving through PATH to it (chmod on the link itself is not needed)
ln -s sh.stub "$BIN_DIR/sh"

RUNNER="$TEST_ROOT/run-install-docker.sh"
cat > "$RUNNER" <<'RUNNER_SCRIPT'
#!/bin/bash
source "$ROOT_DIR/install.sh"
LOG_FILE="$TEST_ROOT/install.log"
install_docker
RUNNER_SCRIPT
chmod 700 "$RUNNER"

# install_docker asks before downloading when stdin is a tty.  util-linux
# script supplies that tty while still letting the test feed an affirmative
# response non-interactively.
printf 'y\n' | /usr/bin/env \
    PATH="$BIN_DIR" ROOT_DIR="$ROOT_DIR" TEST_ROOT="$TEST_ROOT" BIN_DIR="$BIN_DIR" \
    LOG_FILE="$TEST_ROOT/install.log" \
    PANEL_PASSWORD='Test_Bootstrap_1!' \
    /usr/bin/script -qefc "/bin/bash '$RUNNER'" /dev/null \
    > "$TEST_ROOT/runner-output" 2>&1

curl_output=$(<"$TEST_ROOT/curl-output")
sh_argument=$(<"$TEST_ROOT/sh-argument")
[[ "$curl_output" == "$sh_argument" ]]
[[ "$curl_output" != '/tmp/get-docker.sh' ]]
[[ "$curl_output" == /tmp/1panel-docker.*/* ]]
[[ "$(<"$TEST_ROOT/curl-dir-mode")" == 700 ]]
[[ "$(<"$TEST_ROOT/curl-file-mode")" == 600 ]]
[[ "$(<"$TEST_ROOT/sh-dir-mode")" == 700 ]]
[[ "$(<"$TEST_ROOT/sh-file-mode")" == 600 ]]
[[ -f "$TEST_ROOT/script-ran" ]]
[[ ! -e "$curl_output" ]]
# the docker installer script must never inherit the bootstrap password:
# install_docker spawns it through `env -u PANEL_PASSWORD sh`
[[ "$(<"$TEST_ROOT/sh-env-password-count")" == 0 ]]

echo "installer docker script isolation checks passed"
