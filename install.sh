#!/bin/bash

# 1Panel installer for the lanqiguoguo fork.
# Everything is served from this repository's own release channel:
#   - version manifest : https://raw.githubusercontent.com/lanqiguoguo/1Panel/main/stable/latest
#   - upgrade packages : https://github.com/lanqiguoguo/1Panel/releases/download/packages
#
# Usage:
#   bash install.sh                  install the latest stable version
#   bash install.sh v1.10.35-lts     install a specific version
#   bash install.sh -u               uninstall the panel
#
# Non-interactive install: pre-set PANEL_BASE_DIR, PANEL_PORT, PANEL_USERNAME,
# PANEL_PASSWORD, PANEL_ENTRANCE or PANEL_LANG to skip the matching prompt.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

RAW_BASE="https://raw.githubusercontent.com/lanqiguoguo/1Panel/main"
PKG_BASE="https://github.com/lanqiguoguo/1Panel/releases/download/packages"

LOG_FILE="$(pwd)/install.log"
PASSWORD_MASK="**********"

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
    echo "  -u, --uninstall  uninstall the panel"
    echo "  -h, --help       show this help"
}

# set_param FILE KEY VALUE — rewrite "KEY=..." in place without any regex
# escaping of VALUE (passwords may contain sed metacharacters).
function set_param() {
    local file=$1 key=$2 value=$3 tmp
    tmp="${file}.tmp"
    awk -v prefix="$key=" -v value="$value" '
        index($0, prefix) == 1 { print prefix value; next }
        { print }
    ' "$file" > "$tmp" && mv "$tmp" "$file"
}

function fetch() {
    # fetch URL OUTPUT_FILE
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 --connect-timeout 15 "$1" -o "$2"
    else
        wget -q -T 15 -t 3 "$1" -O "$2"
    fi
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
        if ! fetch "$RAW_BASE/stable/latest" "$latest_file" || [[ ! -s "$latest_file" ]]; then
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

function fetch_package() {
    local file_name="1panel-${VERSION}-linux-${ARCH}.tar.gz"
    local url="$PKG_BASE/$file_name"
    EXTRACT_ROOT=$(mktemp -d /tmp/1panel-install.XXXXXX)
    log_info "downloading $url ..."
    if ! fetch "$url" "$EXTRACT_ROOT/$file_name"; then
        log_err "download failed, check that version $VERSION ($ARCH) exists on the release channel"
        exit 1
    fi
    tar -xzf "$EXTRACT_ROOT/$file_name" -C "$EXTRACT_ROOT" || { log_err "extract failed"; exit 1; }
    EXTRACT_DIR="$EXTRACT_ROOT/${file_name%.tar.gz}"
    if [[ ! -x "$EXTRACT_DIR/1panel" || ! -f "$EXTRACT_DIR/1pctl" || ! -d "$EXTRACT_DIR/initscript" || ! -d "$EXTRACT_DIR/lang" ]]; then
        log_err "package layout unexpected, required files missing in $EXTRACT_DIR"
        exit 1
    fi
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
        read -r -p "$(text TXT_SET_PANEL_PORT "set panel port (default $default_port): ")" PANEL_PORT
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
        read -r -p "$(text TXT_SET_PANEL_ENTRANCE "set security entrance (default $default_entrance): ")" PANEL_ENTRANCE
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
        read -r -p "$(text TXT_SET_PANEL_USER "set admin username (default $default_username): ")" PANEL_USERNAME
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
        read -r -s -p "$(text TXT_SET_PANEL_PASSWORD "set admin password (press enter for random): ")" PANEL_PASSWORD
        echo
        if [[ -z "$PANEL_PASSWORD" ]]; then PANEL_PASSWORD=$default_password; fi
        if ! [[ "$PANEL_PASSWORD" =~ ^[a-zA-Z0-9_!@#$%*,.?]{8,30}$ ]]; then
            log_err "$(text TXT_INPUT_PASSWORD_RULE "invalid password format")"
            PANEL_PASSWORD=""
            continue
        fi
        break
    done
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
            curl -fsSL https://get.docker.com | sh 2>&1 | tee -a "$LOG_FILE"
            if ! command -v docker >/dev/null 2>&1; then
                log_warn "docker install failed, you can install it manually later"
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
    set_param /usr/local/bin/1pctl ORIGINAL_PASSWORD "$PANEL_PASSWORD"
    set_param /usr/local/bin/1pctl LANGUAGE "$SELECTED_LANG"

    mkdir -p "$RUN_BASE_DIR/geo/"
    cp -f ./GeoIP.mmdb "$RUN_BASE_DIR/geo/"
    cp -rf ./lang /usr/local/bin/
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
    log_err "panel service did not become active, check 'systemctl status 1panel' and journalctl"
    exit 1
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
    log_info "$(text TXT_PANEL_PASSWORD "password") $PANEL_PASSWORD"
    log_warn "$(text TXT_REMEMBER_YOUR_PASSWORD "keep your credentials safe")"
    # mask the password in the log file but keep the real value inside 1pctl:
    # the backend reads ORIGINAL_* params from there on every start
    awk -v pwd="$PANEL_PASSWORD" -v mask="$PASSWORD_MASK" '{gsub(pwd, mask); print}' \
        "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
}

function do_install() {
    check_root
    check_not_installed
    resolve_version
    detect_arch
    fetch_package
    choose_lang
    set_dir
    set_port
    set_entrance
    set_username
    set_password
    open_firewall_port
    install_docker
    log_info "$(text TXT_CONFIGURE_PANEL_SERVICE "configuring panel service...")"
    install_panel_files
    install_service
    wait_active
    get_ips
    show_result
    rm -rf "$EXTRACT_ROOT"
    log_ok "1Panel $VERSION installed successfully"
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
            -*)
                echo "unknown option: $1"
                usage
                exit 1
                ;;
            *)
                REQUESTED_VERSION="$1"
                shift
                ;;
        esac
    done
    do_install
}

main "$@"
