#!/bin/bash

# 1Panel installer for the lanqiguoguo fork.   revision: 2026-08-27-sha256
# Everything is served from this repository's own release channel:
#   - version manifest : https://raw.githubusercontent.com/lanqiguoguo/1Panel/main/stable/latest
#   - upgrade packages : https://github.com/lanqiguoguo/1Panel/releases/download/packages
#
# Usage:
#   bash install.sh                  install the latest stable version
#   bash install.sh v1.10.35-lts     install a specific version
#   bash install.sh --proxy http://127.0.0.1:7890
#                                    route downloads through an explicit proxy
#                                    (survives sudo, unlike environment variables)
#   bash install.sh --pkg ./1panel-v1.10.35-lts-linux-amd64.tar.gz
#                                    install from a local package, no download
#   bash install.sh -u               uninstall the panel
#
# Non-interactive install: pre-set PANEL_BASE_DIR, PANEL_PORT, PANEL_USERNAME,
# PANEL_PASSWORD, PANEL_ENTRANCE, PANEL_LANG or PANEL_PROXY to skip the
# matching prompt/option.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

RAW_BASE="https://raw.githubusercontent.com/lanqiguoguo/1Panel/main"
PKG_BASE="https://github.com/lanqiguoguo/1Panel/releases/download/packages"

LOG_FILE="$(pwd)/install.log"

REQUESTED_VERSION=""
VERSION=""
ARCH=""
EXTRACT_DIR=""
EXTRACT_ROOT=""
RUN_BASE_DIR=""
SERVICE_MANAGER=""
SELECTED_LANG="en"
LOCAL_IP=""
PUBLIC_IP=""
PROXY_URL="${PANEL_PROXY:-}"
LOCAL_PKG=""

# Keep an environment-supplied bootstrap password in the shell only.  Child
# commands must not inherit it where it could be inspected through /proc.
export -n PANEL_PASSWORD 2>/dev/null || true

function log_msg() {
    local color=$1 message=$2 timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${color}[1Panel ${timestamp}] ${message}${NC}" | tee -a "$LOG_FILE"
}
function log_info() { log_msg "$BLUE" "$1"; }
function log_ok() { log_msg "$GREEN" "$1"; }
function log_warn() { log_msg "$YELLOW" "$1"; }
function log_err() { log_msg "$RED" "$1"; }

function usage() {
    echo "Usage: bash install.sh [OPTIONS] [VERSION]"
    echo ""
    echo "  VERSION          install a specific version, e.g. v1.10.35-lts (default: latest stable)"
    echo "  --proxy URL      route downloads through an explicit proxy, e.g. http://127.0.0.1:7890"
    echo "                   (PANEL_PROXY env does the same; survives sudo unlike exported vars)"
    echo "  --pkg FILE       install from a local package tar.gz instead of downloading"
    echo "  -u, --uninstall  uninstall the panel"
    echo "  -h, --help       show this help"
}

# set_param FILE KEY VALUE — rewrite "KEY=..." in place without any regex
# escaping of VALUE (passwords may contain sed metacharacters).
function set_param() {
    local file=$1 key=$2 value=$3 tmp mode
    tmp="${file}.tmp"
    mode=$(stat -c %a "$file")
    awk -v prefix="$key=" -v value="$value" '
        index($0, prefix) == 1 { print prefix value; next }
        { print }
    ' "$file" > "$tmp" && chmod "$mode" "$tmp" && mv "$tmp" "$file"
}

function fetch() {
    # fetch URL OUTPUT_FILE [MAX_SECS] — resumable, time-bounded, shows progress.
    # Routes through PROXY_URL when set (explicit -x overrides any env proxy).
    local url=$1 out=$2 max_time=${3:-120} attempt
    local proxy_args=()
    [[ -n "$PROXY_URL" ]] && proxy_args=(-x "$PROXY_URL")
    for attempt in 1 2 3; do
        if command -v curl >/dev/null 2>&1; then
            if curl -fL --progress-bar --connect-timeout 15 --max-time "$max_time" "${proxy_args[@]}" -C - "$url" -o "$out"; then
                return 0
            fi
        else
            local wget_ok=0
            if [[ -n "$PROXY_URL" ]]; then
                wget -c -T 60 -t 1 -e use_proxy=yes -e "http_proxy=$PROXY_URL" -e "https_proxy=$PROXY_URL" "$url" -O "$out" && wget_ok=1
            else
                wget -c -T 60 -t 1 "$url" -O "$out" && wget_ok=1
            fi
            [[ $wget_ok -eq 1 ]] && return 0
        fi
        [[ $attempt -lt 3 ]] && { echo "  retrying ($attempt/3)..."; sleep 2; }
    done
    return 1
}

# probe_url URL — preflight connectivity on the active route, prints HTTP code
function probe_url() {
    local code
    if command -v curl >/dev/null 2>&1; then
        local proxy_args=()
        [[ -n "$PROXY_URL" ]] && proxy_args=(-x "$PROXY_URL")
        code=$(curl -sIL -m 8 "${proxy_args[@]}" -o /dev/null -w '%{http_code}' "$1")
    else
        code=$(wget -q -T 8 --spider "$1" && echo 200 || echo 000)
    fi
    echo "$code"
}

TEXT_LOADED=false
# text KEY FALLBACK — localized string once lang files are loaded, English before that
function text() {
    if $TEXT_LOADED && declare -p "$1" >/dev/null 2>&1; then
        eval "echo \"\${$1}\""
    else
        echo "$2"
    fi
}

function check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "$(text TXT_RUN_AS_ROOT "please run as root")"
        exit 1
    fi
}

function check_not_installed() {
    if command -v 1panel >/dev/null 2>&1; then
        log_err "$(text TXT_PANEL_ALREADY_INSTALLED "1Panel is already installed")"
        exit 1
    fi
}

function resolve_version() {
    if [[ -n "$REQUESTED_VERSION" ]]; then
        VERSION="$REQUESTED_VERSION"
    else
        log_info "resolving latest stable version..."
        local latest_file
        latest_file=$(mktemp)
        if ! fetch "$RAW_BASE/stable/latest" "$latest_file" 60 || [[ ! -s "$latest_file" ]]; then
            rm -f "$latest_file"
            log_err "failed to load $RAW_BASE/stable/latest"
            exit 1
        fi
        VERSION=$(tr -d '[:space:]' < "$latest_file")
        rm -f "$latest_file"
    fi
    if [[ ! "$VERSION" =~ ^v[0-9]+(\.[0-9]+)+-[a-z0-9]+([-._][0-9A-Za-z]+)*$ ]]; then
        log_err "invalid version format: $VERSION"
        exit 1
    fi
    log_info "installing version $VERSION"
}

function detect_arch() {
    case "$(uname -m)" in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="armv7" ;;
        *) log_err "unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
}

# prepare_extracted_pkg TARBALL_PATH — extract into a fresh temp dir and verify layout
function prepare_extracted_pkg() {
    local tarball=$1 base
    base=$(basename "$tarball")
    base=${base%.tar.gz}
    tar -xzf "$tarball" -C "$EXTRACT_ROOT" || { log_err "extract failed"; exit 1; }
    EXTRACT_DIR="$EXTRACT_ROOT/$base"
    if [[ ! -x "$EXTRACT_DIR/1panel" || ! -f "$EXTRACT_DIR/1pctl" || ! -d "$EXTRACT_DIR/initscript" || ! -d "$EXTRACT_DIR/lang" ]]; then
        log_err "package layout unexpected, required files missing in $EXTRACT_DIR"
        exit 1
    fi
}

function load_local_pkg() {
    if [[ ! -f "$LOCAL_PKG" ]]; then
        log_err "package file not found: $LOCAL_PKG"
        exit 1
    fi
    # verification is optional offline: only check when the checksum sidecar
    # was fetched alongside the package
    local checksum_file="${LOCAL_PKG}.sha256.txt"
    if [[ -f "$checksum_file" ]]; then
        verify_sha256 "$LOCAL_PKG" "$checksum_file"
    else
        log_warn "no checksum file next to $LOCAL_PKG, skipping sha256 verification"
    fi
    local base
    base=$(basename "$LOCAL_PKG")
    if [[ "$base" =~ ^1panel-(v[0-9]+(\.[0-9]+)+-[a-z0-9]+([-._][0-9A-Za-z]+)*)-linux-[a-z0-9]+\.tar\.gz$ ]]; then
        VERSION="${BASH_REMATCH[1]}"
    else
        log_err "cannot derive version from file name (expected 1panel-<version>-linux-<arch>.tar.gz): $base"
        exit 1
    fi
    log_info "installing version $VERSION from local package"
    EXTRACT_ROOT=$(mktemp -d /tmp/1panel-install.XXXXXX)
    prepare_extracted_pkg "$LOCAL_PKG"
}

# verify_sha256 TARBALL CHECKSUM_FILE — compare the digest recorded in a
# sha256sum-generated checksum file ("<hash>  <filename>") against the actual
# hash of the downloaded tarball. Any problem (unreadable file, malformed
# digest, mismatch) aborts the install: fail closed.
function verify_sha256() {
    local tarball=$1 checksum_file=$2 expected actual
    if [[ ! -r "$checksum_file" ]]; then
        log_err "checksum file missing or unreadable: $checksum_file"
        exit 1
    fi
    expected=$(awk 'NF{print $1; exit}' "$checksum_file")
    if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
        log_err "checksum file does not start with a valid sha256 digest: $checksum_file"
        exit 1
    fi
    if ! actual=$(sha256sum "$tarball"); then
        log_err "failed to compute sha256 of $tarball"
        exit 1
    fi
    actual=${actual%% *}
    if [[ "$expected" != "$actual" ]]; then
        log_err "sha256 mismatch for $(basename "$tarball"), refusing to install:"
        log_err "  expected: $expected"
        log_err "  actual:   $actual"
        exit 1
    fi
    log_ok "sha256 verified: $actual"
}

# Downloads land in a private per-run temp directory. A fixed /tmp path shared
# across runs and users would allow symlink swaps or tampering with the
# partial file between download and install; resume still works within a
# single run because the retry loop in fetch appends to the same partial file.
DOWNLOAD_DIR=""
DOCKER_SCRIPT_DIR=""

function fetch_package() {
    local file_name="1panel-${VERSION}-linux-${ARCH}.tar.gz"
    local checksum_name="${file_name}.sha256.txt"
    local url="$PKG_BASE/$file_name"
    if [[ -n "$PROXY_URL" ]]; then
        log_info "using explicit proxy: $PROXY_URL"
    else
        log_info "no --proxy given; downloads follow http(s)_proxy env vars when present"
    fi
    local code
    code=$(probe_url "$url")
    case "$code" in
        200) ;;
        unknown)
            log_warn "connectivity preflight unavailable, proceeding anyway"
            ;;
        *)
            if [[ -n "$PROXY_URL" ]]; then
                log_err "preflight through proxy $PROXY_URL failed (HTTP $code);"
                log_err "check that the proxy is reachable from this machine"
            else
                log_err "direct connectivity to the release channel failed (HTTP $code)."
                log_err "GitHub release assets are commonly unreachable without a proxy; retry with:"
                log_err "  sudo bash install.sh --proxy http://<proxy-host>:<port>"
                log_err "or install offline from a manually downloaded copy:"
                log_err "  sudo bash install.sh --pkg ./$file_name"
            fi
            exit 1
            ;;
    esac
    DOWNLOAD_DIR=$(mktemp -d /tmp/1panel-download.XXXXXX) || {
        log_err "failed to create a private download directory"
        exit 1
    }
    log_info "downloading $url ..."
    if ! fetch "$url" "$DOWNLOAD_DIR/$file_name" 1800; then
        log_err "download failed or timed out"
        exit 1
    fi
    log_info "downloading $PKG_BASE/$checksum_name ..."
    if ! fetch "$PKG_BASE/$checksum_name" "$DOWNLOAD_DIR/$checksum_name" 120; then
        log_err "checksum file $PKG_BASE/$checksum_name is unavailable,"
        log_err "refusing to install an unverified package"
        exit 1
    fi
    verify_sha256 "$DOWNLOAD_DIR/$file_name" "$DOWNLOAD_DIR/$checksum_name"
    EXTRACT_ROOT=$(mktemp -d /tmp/1panel-install.XXXXXX)
    prepare_extracted_pkg "$DOWNLOAD_DIR/$file_name"
}

# Load one of the bundled lang files so prompts are localized like upstream.
function choose_lang() {
    local selected="en" answer
    if [[ -n "$PANEL_LANG" ]]; then
        selected="$PANEL_LANG"
    elif [[ -t 0 ]]; then
        local codes=()
        for f in "$EXTRACT_DIR"/lang/*.sh; do
            codes+=("$(basename "$f" .sh)")
        done
        echo "available languages: ${codes[*]}"
        read -r -p "select language [en]: " answer
        [[ -n "$answer" ]] && selected="$answer"
    fi
    local langfile="$EXTRACT_DIR/lang/$selected.sh"
    if [[ ! -f "$langfile" ]]; then
        langfile="$EXTRACT_DIR/lang/en.sh"
        selected="en"
    fi
    # shellcheck disable=SC1090
    source "$langfile"
    SELECTED_LANG="$selected"
    TEXT_LOADED=true
}

function set_dir() {
    if [[ -n "$PANEL_BASE_DIR" ]]; then
        RUN_BASE_DIR="$PANEL_BASE_DIR/1panel"
        mkdir -p "$RUN_BASE_DIR"
        return
    fi
    if ! read -t 120 -r -p "$(text TXT_SET_INSTALL_DIR "set install dir (default /opt): ")" PANEL_BASE_DIR; then
        PANEL_BASE_DIR=/opt
    fi
    if [[ -z "$PANEL_BASE_DIR" ]]; then
        PANEL_BASE_DIR=/opt
    fi
    if [[ "$PANEL_BASE_DIR" != /* ]]; then
        log_err "$(text TXT_PROVIDE_FULL_PATH "please provide an absolute path")"
        set_dir
        return
    fi
    RUN_BASE_DIR="$PANEL_BASE_DIR/1panel"
    mkdir -p "$RUN_BASE_DIR"
    log_info "$(text TXT_SELECTED_INSTALL_PATH "install path") $PANEL_BASE_DIR"
}

function set_port() {
    if [[ -n "$PANEL_PORT" ]]; then return; fi
    local default_port=$((RANDOM % 55535 + 10000))
    while true; do
        read -r -p "$(text TXT_SET_PANEL_PORT "set panel port (default is") $default_port): " PANEL_PORT
        if [[ -z "$PANEL_PORT" ]]; then PANEL_PORT=$default_port; fi
        if ! [[ "$PANEL_PORT" =~ ^[1-9][0-9]{0,4}$ && "$PANEL_PORT" -le 65535 ]]; then
            log_err "$(text TXT_INPUT_PORT_NUMBER "invalid port number")"
            PANEL_PORT=""
            continue
        fi
        if ss -tlun 2>/dev/null | grep -q ":$PANEL_PORT " || netstat -tlun 2>/dev/null | grep -q ":$PANEL_PORT "; then
            log_err "$(text TXT_PORT_OCCUPIED "port occupied") $PANEL_PORT"
            PANEL_PORT=""
            continue
        fi
        break
    done
}

function set_entrance() {
    if [[ -n "$PANEL_ENTRANCE" ]]; then return; fi
    local default_entrance
    default_entrance=$(head -c 16 /dev/urandom | md5sum | head -c 10)
    while true; do
        read -r -p "$(text TXT_SET_PANEL_ENTRANCE "set security entrance (default is") $default_entrance): " PANEL_ENTRANCE
        if [[ -z "$PANEL_ENTRANCE" ]]; then PANEL_ENTRANCE=$default_entrance; fi
        if ! [[ "$PANEL_ENTRANCE" =~ ^[a-zA-Z0-9_]{3,30}$ ]]; then
            log_err "$(text TXT_INPUT_ENTRANCE_RULE "invalid entrance format")"
            PANEL_ENTRANCE=""
            continue
        fi
        break
    done
}

function set_username() {
    if [[ -n "$PANEL_USERNAME" ]]; then return; fi
    local default_username
    default_username=$(head -c 16 /dev/urandom | md5sum | head -c 10)
    while true; do
        read -r -p "$(text TXT_SET_PANEL_USER "set admin username (default is") $default_username): " PANEL_USERNAME
        if [[ -z "$PANEL_USERNAME" ]]; then PANEL_USERNAME=$default_username; fi
        if ! [[ "$PANEL_USERNAME" =~ ^[a-zA-Z0-9_]{3,30}$ ]]; then
            log_err "$(text TXT_INPUT_USERNAME_RULE "invalid username format")"
            PANEL_USERNAME=""
            continue
        fi
        break
    done
}

function set_password() {
    if [[ -n "$PANEL_PASSWORD" ]]; then return; fi
    local default_password
    default_password=$(head -c 16 /dev/urandom | md5sum | head -c 10)
    while true; do
        local tty_fd
        if ! exec {tty_fd}<>/dev/tty 2>/dev/null; then
            log_err "PANEL_PASSWORD must be set for non-interactive installs"
            exit 1
        fi
        local password_prompt
        # never print the generated default: it would be captured in the
        # terminal scrollback buffer; an empty input silently uses it
        password_prompt="$(text TXT_SET_PANEL_PASSWORD "set admin password"): "
        printf '%s' "$password_prompt" >&"$tty_fd"
        if ! IFS= read -r -s PANEL_PASSWORD <&"$tty_fd"; then
            printf '\n' >&"$tty_fd"
            exec {tty_fd}>&-
            log_err "failed to read panel password"
            exit 1
        fi
        printf '\n' >&"$tty_fd"
        exec {tty_fd}>&-
        if [[ -z "$PANEL_PASSWORD" ]]; then PANEL_PASSWORD=$default_password; fi
        if ! [[ "$PANEL_PASSWORD" =~ ^[a-zA-Z0-9_!@#$%*,.?]{8,30}$ ]]; then
            log_err "$(text TXT_INPUT_PASSWORD_RULE "invalid password format")"
            PANEL_PASSWORD=""
            continue
        fi
        break
    done
}

# write_initial_password stores the bootstrap credential only long enough for
# the first service start.  The backend removes it after the initial database
# migration; until then it is readable only by root.
function write_initial_password() {
    # PANEL_PASSWORD may come straight from the environment (set_password is
    # skipped when it is preset), so re-validate before persisting anything
    if ! [[ "$PANEL_PASSWORD" =~ ^[a-zA-Z0-9_!@#$%*,.?]{8,30}$ ]]; then
        log_err "$(text TXT_INPUT_PASSWORD_RULE "invalid password format")"
        exit 1
    fi
    local secret_dir="$RUN_BASE_DIR/conf"
    local secret_file="$secret_dir/initial-password"
    mkdir -p "$secret_dir" || {
        log_err "failed to create the panel secret directory"
        exit 1
    }
    if ! (umask 077 && printf '%s\n' "$PANEL_PASSWORD" > "$secret_file"); then
        log_err "failed to write the initial panel password"
        exit 1
    fi
    chmod 600 "$secret_file" || {
        log_err "failed to secure the initial panel password"
        exit 1
    }
}

function clear_install_password_export() {
    # PANEL_PASSWORD may have been imported from the environment.  Unexport it
    # before starting a non-systemd service so the daemon cannot inherit it.
    export -n PANEL_PASSWORD 2>/dev/null || true
}

function clear_install_password() {
    clear_install_password_export
    unset PANEL_PASSWORD
}

function install_docker() {
    if command -v docker >/dev/null 2>&1; then
        log_info "docker detected: $(docker --version 2>/dev/null)"
    else
        local answer=""
        if [[ -t 0 ]]; then
            read -r -p "docker not found, install it now? [y/N]: " answer
        fi
        if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
            log_info "installing docker via get.docker.com ..."
            local proxy_args=()
            local docker_script
            [[ -n "$PROXY_URL" ]] && proxy_args=(-x "$PROXY_URL")
            DOCKER_SCRIPT_DIR=$(mktemp -d /tmp/1panel-docker.XXXXXX) || {
                log_err "failed to create a private directory for the docker install script"
                log_warn "docker skipped; install it manually (make sure the apt/yum sources can be reached)"
                return
            }
            chmod 700 "$DOCKER_SCRIPT_DIR" || {
                rm -rf -- "$DOCKER_SCRIPT_DIR"
                DOCKER_SCRIPT_DIR=""
                log_err "failed to secure the docker install script directory"
                log_warn "docker skipped; install it manually (make sure the apt/yum sources can be reached)"
                return
            }
            docker_script=$(mktemp "$DOCKER_SCRIPT_DIR/get-docker.XXXXXX") || {
                rm -rf -- "$DOCKER_SCRIPT_DIR"
                DOCKER_SCRIPT_DIR=""
                log_err "failed to create the docker install script"
                log_warn "docker skipped; install it manually (make sure the apt/yum sources can be reached)"
                return
            }
            chmod 600 "$docker_script" || {
                rm -rf -- "$DOCKER_SCRIPT_DIR"
                DOCKER_SCRIPT_DIR=""
                log_err "failed to secure the docker install script"
                log_warn "docker skipped; install it manually (make sure the apt/yum sources can be reached)"
                return
            }
            if ! curl -fsSL --connect-timeout 15 "${proxy_args[@]}" https://get.docker.com -o "$docker_script"; then
                rm -rf -- "$DOCKER_SCRIPT_DIR"
                DOCKER_SCRIPT_DIR=""
                log_err "failed to download the docker install script${PROXY_URL:+ through $PROXY_URL}"
                log_warn "docker skipped; install it manually (make sure the apt/yum sources can be reached)"
                return
            fi
            # export standard vars so the script's internal apt/yum/curl calls
            # inherit the same route as everything else in this installer
            # strip PANEL_PASSWORD at the spawn: the untrusted docker
            # installer script must never see the bootstrap credential
            if [[ -n "$PROXY_URL" ]]; then
                http_proxy="$PROXY_URL" https_proxy="$PROXY_URL" \
                    HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL" \
                    env -u PANEL_PASSWORD sh "$docker_script" 2>&1 | tee -a "$LOG_FILE"
            else
                env -u PANEL_PASSWORD sh "$docker_script" 2>&1 | tee -a "$LOG_FILE"
            fi
            rm -rf -- "$DOCKER_SCRIPT_DIR"
            DOCKER_SCRIPT_DIR=""
            if ! command -v docker >/dev/null 2>&1; then
                log_warn "docker install failed${PROXY_URL:+ (was routed through $PROXY_URL)}"
                log_warn "docker skipped; install it manually and rerun app-store features afterwards"
                return
            fi
        else
            log_warn "docker skipped, app store features need docker"
            return
        fi
    fi
    if ! docker compose version >/dev/null 2>&1 && ! docker-compose version >/dev/null 2>&1; then
        log_warn "docker compose plugin not found, app store features may be limited"
    fi
}

function open_firewall_port() {
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --zone=public --add-port="$PANEL_PORT"/tcp --permanent >/dev/null
        firewall-cmd --reload >/dev/null
        log_info "firewalld port opened: $PANEL_PORT/tcp"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        ufw allow "$PANEL_PORT"/tcp >/dev/null
        log_info "ufw port opened: $PANEL_PORT/tcp"
    fi
}

function install_panel_files() {
    cd "$EXTRACT_DIR" || exit 1
    cp ./1panel /usr/local/bin && chmod +x /usr/local/bin/1panel
    ln -sf /usr/local/bin/1panel /usr/bin/1panel
    cp ./1pctl /usr/local/bin && chmod +x /usr/local/bin/1pctl
    ln -sf /usr/local/bin/1pctl /usr/bin/1pctl

    set_param /usr/local/bin/1pctl BASE_DIR "$PANEL_BASE_DIR"
    set_param /usr/local/bin/1pctl ORIGINAL_VERSION "$VERSION"
    set_param /usr/local/bin/1pctl ORIGINAL_PORT "$PANEL_PORT"
    set_param /usr/local/bin/1pctl ORIGINAL_ENTRANCE "$PANEL_ENTRANCE"
    set_param /usr/local/bin/1pctl ORIGINAL_USERNAME "$PANEL_USERNAME"
    set_param /usr/local/bin/1pctl LANGUAGE "$SELECTED_LANG"
    chmod +x /usr/local/bin/1pctl /usr/local/bin/1panel

    mkdir -p "$RUN_BASE_DIR/geo/"
    cp -f ./GeoIP.mmdb "$RUN_BASE_DIR/geo/"
    cp -rf ./lang /usr/local/bin/
    # the panel creates these on first boot; pre-create so 1pctl works
    # immediately after install (sqlite reports CANTOPEN as "out of memory")
    mkdir -p "$RUN_BASE_DIR/db" "$RUN_BASE_DIR/log" "$RUN_BASE_DIR/tmp" "$RUN_BASE_DIR/cache" "$RUN_BASE_DIR/backup"
    write_initial_password
}

function install_service() {
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        cp ./initscript/1panel.service /etc/systemd/system/
        systemctl enable 1panel.service >/dev/null 2>&1
        systemctl daemon-reload
        systemctl start 1panel.service
        SERVICE_MANAGER="systemd"
    elif [ -f /etc/rc.common ]; then
        cp ./initscript/1paneld.procd /etc/init.d/1paneld
        chmod +x /etc/init.d/1paneld
        /etc/init.d/1paneld enable
        /etc/init.d/1paneld start
        SERVICE_MANAGER="procd"
    elif [ -f /sbin/openrc-run ]; then
        cp ./initscript/1paneld.openrc /etc/init.d/1paneld
        chmod +x /etc/init.d/1paneld
        rc-update add 1paneld default
        /etc/init.d/1paneld start
        SERVICE_MANAGER="openrc"
    else
        cp ./initscript/1paneld.init /etc/init.d/1paneld
        chmod +x /etc/init.d/1paneld
        /etc/init.d/1paneld enable
        /etc/init.d/1paneld start
        SERVICE_MANAGER="sysvinit"
    fi
    cp -rf ./initscript "$RUN_BASE_DIR/"
}

function panel_running() {
    case "$SERVICE_MANAGER" in
        systemd)
            systemctl is-active --quiet 1panel ;;
        *)
            service 1paneld status >/dev/null 2>&1 || pgrep -x 1panel >/dev/null ;;
    esac
}

function wait_active() {
    local attempt max_attempts=15
    for attempt in $(seq 1 "$max_attempts"); do
        if panel_running; then
            return 0
        fi
        sleep 2
    done
    # last resort: the process may be alive even when the init system's status
    # query misreports (openrc not booted, minimal images); check pgrep directly
    if pgrep -x 1panel >/dev/null 2>&1; then
        log_warn "service status query failed but the panel process is running"
        return 0
    fi
    log_warn "panel service did not report active within $((max_attempts * 2))s"
    log_warn "installation files are in place; diagnose with 'systemctl status 1panel' or '/etc/init.d/1paneld status'"
    log_warn "if the panel never comes up: bash install.sh -u cleans everything for a retry"
    return 1
}

function get_ips() {
    LOCAL_IP=$(ip -4 addr show scope global 2>/dev/null | grep -oE 'inet[[:space:]]+([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1 | awk '{print $2}')
    if [[ -z "$LOCAL_IP" ]]; then LOCAL_IP="127.0.0.1"; fi
    PUBLIC_IP=$(curl -s -m 5 https://api64.ipify.org 2>/dev/null)
    if [[ -z "$PUBLIC_IP" ]]; then PUBLIC_IP="$LOCAL_IP"; fi
    if [[ "$PUBLIC_IP" == *:* ]]; then PUBLIC_IP="[$PUBLIC_IP]"; fi
}

function show_result() {
    log_ok "$(text TXT_BROWSER_ACCESS_PANEL "access the panel in your browser")"
    log_info "external: http://$PUBLIC_IP:$PANEL_PORT/$PANEL_ENTRANCE"
    log_info "internal: http://$LOCAL_IP:$PANEL_PORT/$PANEL_ENTRANCE"
    log_info "$(text TXT_PANEL_USER "username") $PANEL_USERNAME"
    # Passwords must bypass stdout because installer output is commonly piped
    # through tee.  If there is no controlling terminal (for example, a
    # non-interactive install with PANEL_PASSWORD), do not print the secret.
    local tty_fd
    if exec {tty_fd}>/dev/tty 2>/dev/null; then
        local timestamp password_label
        timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        password_label=$(text TXT_PANEL_PASSWORD "password")
        printf '%b[1Panel %s] %s %s%b\n' "$BLUE" "$timestamp" "$password_label" "$PANEL_PASSWORD" "$NC" >&"$tty_fd"
        exec {tty_fd}>&-
    fi
    log_warn "$(text TXT_REMEMBER_YOUR_PASSWORD "keep your credentials safe")"
}

function do_install() {
    check_root
    check_not_installed
    if [[ -n "$LOCAL_PKG" ]]; then
        load_local_pkg
    else
        resolve_version
        detect_arch
        fetch_package
    fi
    choose_lang
    set_dir
    set_port
    set_entrance
    set_username
    set_password
    clear_install_password_export
    open_firewall_port
    install_docker
    log_info "$(text TXT_CONFIGURE_PANEL_SERVICE "configuring panel service...")"
    install_panel_files
    install_service
    if wait_active; then
        get_ips
        show_result
        clear_install_password
        log_ok "1Panel $VERSION installed successfully"
    else
        clear_install_password
        log_warn "1Panel $VERSION installed, but service startup needs a manual check (see warnings above)"
    fi
}

function do_uninstall() {
    check_root
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        systemctl stop 1panel.service >/dev/null 2>&1
        systemctl disable 1panel.service >/dev/null 2>&1
        rm -f /etc/systemd/system/1panel.service
        systemctl daemon-reload
        systemctl reset-failed 2>/dev/null
    elif [ -f /etc/rc.common ]; then
        /etc/init.d/1paneld stop >/dev/null 2>&1
        /etc/init.d/1paneld disable >/dev/null 2>&1
        rm -f /etc/init.d/1paneld
    elif [ -f /sbin/openrc-run ]; then
        rc-service 1paneld stop >/dev/null 2>&1
        rc-update del 1paneld >/dev/null 2>&1
        rm -f /etc/init.d/1paneld
    else
        service 1paneld stop >/dev/null 2>&1
        rm -f /etc/init.d/1paneld
    fi
    rm -f /usr/local/bin/1panel /usr/local/bin/1pctl /usr/bin/1panel /usr/bin/1pctl
    rm -rf /usr/local/bin/lang
    local base_dir="/opt" answer
    if [[ -f /opt/1panel/conf/app.yaml ]]; then
        base_dir=$(grep '^  base_dir:' /opt/1panel/conf/app.yaml | awk '{print $2}')
        [[ -z "$base_dir" ]] && base_dir="/opt"
    fi
    read -r -p "remove panel data under ${base_dir}/1panel? [y/N]: " answer
    if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
        rm -rf "${base_dir}/1panel"
        log_ok "panel data removed"
    else
        log_ok "panel data kept under ${base_dir}/1panel"
    fi
    log_ok "1Panel uninstalled"
}

function main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -u | --uninstall)
                do_uninstall
                exit 0
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            --proxy)
                if [[ -z "${2:-}" ]]; then
                    echo "--proxy requires a URL"
                    usage
                    exit 1
                fi
                PROXY_URL="$2"
                shift 2
                ;;
            --pkg)
                if [[ -z "${2:-}" ]]; then
                    echo "--pkg requires a file path"
                    usage
                    exit 1
                fi
                LOCAL_PKG="$2"
                shift 2
                ;;
            -*)
                echo "unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -n "$REQUESTED_VERSION" ]]; then
                    echo "unexpected extra argument: $1"
                    usage
                    exit 1
                fi
                REQUESTED_VERSION="$1"
                shift
                ;;
        esac
    done
    if [[ -n "$PROXY_URL" && ! "$PROXY_URL" =~ ^(https?|socks5h?):// ]]; then
        echo "invalid proxy URL (expected http:// https:// socks5:// socks5h://): $PROXY_URL"
        exit 1
    fi
    do_install
}

# per-run temp directories; removed on every exit path, success or failure
function cleanup_temp_dirs() {
    [[ -n "$EXTRACT_ROOT" ]] && rm -rf "$EXTRACT_ROOT"
    [[ -n "$DOWNLOAD_DIR" ]] && rm -rf "$DOWNLOAD_DIR"
    [[ -n "$DOCKER_SCRIPT_DIR" ]] && rm -rf -- "$DOCKER_SCRIPT_DIR"
    return 0
}
trap cleanup_temp_dirs EXIT

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
