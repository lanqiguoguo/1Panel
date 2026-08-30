#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SECRET_VALUE='InstallOnly_Password1!'

if grep -Eq '^ORIGINAL_PASSWORD=' "$ROOT_DIR/ci/resources/1pctl"; then
    echo "1pctl template must not contain a password" >&2
    exit 1
fi
if grep -Eq 'set_param[[:space:]].*ORIGINAL_PASSWORD' "$ROOT_DIR/install.sh"; then
    echo "installer must not persist ORIGINAL_PASSWORD in 1pctl" >&2
    exit 1
fi
if grep -Eq 'log_(info|ok|warn|err)[[:space:]].*\$PANEL_PASSWORD' "$ROOT_DIR/install.sh"; then
    echo "installer must not send PANEL_PASSWORD through the logging helpers" >&2
    exit 1
fi
if grep -Eq 'awk[[:space:]]+-v[[:space:]]+pwd=|gsub\(pwd' "$ROOT_DIR/install.sh"; then
    echo "installer must not expose or rewrite the password with awk" >&2
    exit 1
fi
# every bundled password prompt must be free of the generated default value:
# the old templates ended with an open paren awaiting the default, e.g.
# "... (default is" / "... (默认是" — no value may contain an unbalanced one
for langfile in "$ROOT_DIR"/ci/resources/lang/*.sh; do
    if grep -Eq '^TXT_SET_PANEL_PASSWORD=.*\([^)]*"' "$langfile"; then
        echo "lang file $(basename "$langfile") still mentions a default in TXT_SET_PANEL_PASSWORD" >&2
        exit 1
    fi
done
# install.sh must not print the generated default in the password prompt
if grep -Eq 'TXT_SET_PANEL_PASSWORD[^\n]*\$default_password|set admin password \(default is' "$ROOT_DIR/install.sh"; then
    echo "install.sh password prompt must not print the generated default password" >&2
    exit 1
fi

TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
chmod 755 "$TEST_ROOT"

(
    # shellcheck disable=SC1090
    source "$ROOT_DIR/install.sh" || {
        source_status=$?
        exit "$source_status"
    }
    trap - EXIT
    RUN_BASE_DIR="$TEST_ROOT/1panel"
    PANEL_PASSWORD="$SECRET_VALUE"
    write_initial_password
)

SECRET_FILE="$TEST_ROOT/1panel/conf/initial-password"
[[ -f "$SECRET_FILE" ]]
[[ "$(stat -c '%a' "$SECRET_FILE")" == 600 ]]
[[ "$(<"$SECRET_FILE")" == "$SECRET_VALUE" ]]

if [[ "$(id -u)" == 0 ]]; then
    [[ "$(stat -c '%u:%g' "$SECRET_FILE")" == 0:0 ]]
    if command -v runuser >/dev/null 2>&1 && runuser -u nobody -- cat "$SECRET_FILE" >/dev/null 2>&1; then
        echo "unprivileged users can read the initial password" >&2
        exit 1
    fi
fi

echo "installer password persistence checks passed"

# write_initial_password must reject passwords that fail the format rule
# (they can reach it when PANEL_PASSWORD is preset from the environment).
BAD_PASSWORDS=(
    'short'
    '中文密码中文密码'
    'has space in it'
    'Contains-A-Hyphen1!'
    '1234567'
)
for bad_pw in "${BAD_PASSWORDS[@]}"; do
    # subshell + || : the function calls exit 1, which must not kill this
    # test script (set -e would abort on a bare failing subshell)
    bad_status=0
    (   # shellcheck disable=SC1090
        source "$ROOT_DIR/install.sh"
        trap - EXIT
        LOG_FILE="$TEST_ROOT/reject.log"
        RUN_BASE_DIR="$TEST_ROOT/reject"
        PANEL_PASSWORD="$bad_pw"
        write_initial_password
    ) || bad_status=$?
    if [[ $bad_status -eq 0 ]]; then
        echo "write_initial_password accepted invalid password: $bad_pw" >&2
        exit 1
    fi
done
if [[ -e "$TEST_ROOT/reject/conf/initial-password" ]]; then
    echo "write_initial_password wrote a file for an invalid password" >&2
    exit 1
fi
echo "installer invalid password rejection checks passed"

# set_password must return immediately (no prompt, no output) when
# PANEL_PASSWORD is preset from the environment
preset_output=$(
    # shellcheck disable=SC1090
    source "$ROOT_DIR/install.sh"
    trap - EXIT
    PANEL_PASSWORD="$SECRET_VALUE"
    set_password
    printf '%s' "$PANEL_PASSWORD"
)
if [[ "$preset_output" != "$SECRET_VALUE" ]]; then
    echo "set_password changed or echoed a preset PANEL_PASSWORD" >&2
    exit 1
fi
echo "installer preset password short-circuit check passed"

LOG_TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT" "$LOG_TEST_ROOT"' EXIT

(
    # shellcheck disable=SC1090
    source "$ROOT_DIR/install.sh" || {
        source_status=$?
        exit "$source_status"
    }
    trap - EXIT
    LOG_FILE="$LOG_TEST_ROOT/install.log"
    PANEL_PASSWORD="$SECRET_VALUE"
    PANEL_USERNAME='admin'
    PANEL_PORT='9999'
    PANEL_ENTRANCE='secure'
    PUBLIC_IP='198.51.100.10'
    LOCAL_IP='192.0.2.10'
    show_result
) 2>&1 | tee "$LOG_TEST_ROOT/tee-output" >"$LOG_TEST_ROOT/console-output"

if grep -Fq "$SECRET_VALUE" "$LOG_TEST_ROOT/install.log" "$LOG_TEST_ROOT/tee-output" "$LOG_TEST_ROOT/console-output"; then
    echo "installer password leaked to install.log or captured output" >&2
    exit 1
fi
if ! grep -Fq 'username admin' "$LOG_TEST_ROOT/install.log"; then
    echo "installer result output lost the non-secret username" >&2
    exit 1
fi

echo "installer result logging checks passed"
