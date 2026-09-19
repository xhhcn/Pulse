#!/bin/bash
#
# Pulse Client Installation Script for Linux and macOS
# Usage: curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- --id YOUR_ID --server http://YOUR_SERVER:8008
#

set -e

# Detect OS early — used throughout the script
OS=$(uname -s)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INSTALL_DIR="/opt/pulse"
SERVICE_NAME="pulse-client"
UPDATE_SERVICE_NAME="pulse-client-update"
GITHUB_REPO="https://raw.githubusercontent.com/xhhcn/Pulse/main/client"
CLIENT_PORT="9090"
AGENT_NAME=""
SECRET=""
AUTO_UPDATE=true
UPDATE_INTERVAL="daily"

# macOS launchd constants
MACOS_PLIST_LABEL="com.pulse.client"
MACOS_UPDATE_PLIST_LABEL="com.pulse.client.update"
MACOS_PLIST_DIR="/Library/LaunchDaemons"
MACOS_PLIST_PATH="${MACOS_PLIST_DIR}/${MACOS_PLIST_LABEL}.plist"
MACOS_UPDATE_PLIST_PATH="${MACOS_PLIST_DIR}/${MACOS_UPDATE_PLIST_LABEL}.plist"

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                  Pulse Client Installer                   ║"
    echo "║           Lightweight Server Monitoring Agent             ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print message functions
info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

reject_multiline_value() {
    local label="$1"
    local value="$2"
    if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
        error "${label} must not contain newlines"
    fi
}

validate_config_values() {
    reject_multiline_value "Agent ID" "$AGENT_ID"
    reject_multiline_value "Agent name" "$AGENT_NAME"
    reject_multiline_value "Server URL" "$SERVER_BASE"
    reject_multiline_value "Client port" "$CLIENT_PORT"
    reject_multiline_value "Secret" "$SECRET"
    reject_multiline_value "Update interval" "$UPDATE_INTERVAL"
}

systemd_escape_env() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//%/%%}"
    printf '%s' "$value"
}

xml_escape() {
    local value="$1"
    value="${value//&/&amp;}"
    value="${value//</&lt;}"
    value="${value//>/&gt;}"
    value="${value//\"/&quot;}"
    value="${value//\'/&apos;}"
    printf '%s' "$value"
}

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "Please run as root (use sudo)"
    fi
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --id)
                AGENT_ID="$2"
                shift 2
                ;;
            --name|--agent-name)
                AGENT_NAME="$2"
                shift 2
                ;;
            --server)
                SERVER_BASE="$2"
                shift 2
                ;;
            --port)
                CLIENT_PORT="$2"
                shift 2
                ;;
            --secret)
                SECRET="$2"
                shift 2
                ;;
            --auto-update)
                AUTO_UPDATE=true
                shift
                ;;
            --no-auto-update)
                AUTO_UPDATE=false
                shift
                ;;
            --update-interval)
                UPDATE_INTERVAL="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
}

# Show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Supported OS: Linux (systemd), macOS (launchd)"
    echo ""
    echo "Options:"
    echo "  --id ID              Agent ID (required, must match server config)"
    echo "  --name NAME          Agent display name (optional, defaults to ID)"
    echo "  --server URL         Server base URL (required, e.g., http://your-server:8008)"
    echo "  --port PORT          Client port (optional, default: 9090)"
    echo "  --secret SECRET      Secret for authentication (optional)"
    echo "  --auto-update        Enable auto-update (default: enabled)"
    echo "  --no-auto-update     Disable auto-update"
    echo "  --update-interval T  Update check interval (default: daily)"
    echo "                       Linux values: daily, hourly, weekly, or OnCalendar expression"
    echo "                       macOS values: daily, hourly, weekly"
    echo "  --help, -h           Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --id my-server-1 --server http://monitor.example.com:8008 --secret my-secret"
    echo "  $0 --id my-server-1 --server http://monitor.example.com:8008 --no-auto-update"
    echo ""
    echo "Or using curl:"
    echo "  curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- --id my-server-1 --server http://monitor.example.com:8008 --secret my-secret"
}

# Prompt for required values if not provided
prompt_values() {
    if [ -z "$AGENT_ID" ]; then
        read -r -p "Enter Agent ID (must match server config): " AGENT_ID
        [ -z "$AGENT_ID" ] && error "Agent ID is required"
    fi

    if [ -z "$SERVER_BASE" ]; then
        read -r -p "Enter Server URL (e.g., http://your-server:8008): " SERVER_BASE
        [ -z "$SERVER_BASE" ] && error "Server URL is required"
    fi

    if [ -z "$AGENT_NAME" ]; then
        AGENT_NAME="$AGENT_ID"
    fi
}

# Detect OS and architecture, set BINARY_NAME accordingly
detect_arch() {
    local arch
    arch=$(uname -m)
    case "${OS}-${arch}" in
        Linux-x86_64|Linux-amd64)
            BINARY_NAME="probe-client"
            ;;
        Linux-aarch64|Linux-arm64)
            BINARY_NAME="probe-client-arm64"
            ;;
        Darwin-x86_64|Darwin-amd64)
            BINARY_NAME="probe-client-darwin-amd64"
            ;;
        Darwin-arm64|Darwin-aarch64)
            BINARY_NAME="probe-client-darwin-arm64"
            ;;
        *)
            error "Unsupported OS/architecture: ${OS}/${arch}"
            ;;
    esac
    info "Detected OS: ${OS}, architecture: ${arch} → ${BINARY_NAME}"
}

# Compute SHA-256 of a file (works on both Linux and macOS)
sha256_file() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "NOHASH_$(date +%s)"
    fi
}

# Validate that a downloaded binary has the correct magic bytes for the current OS
validate_binary() {
    local file="$1"
    [ ! -s "$file" ] && return 1
    if [[ "$OS" == "Darwin" ]]; then
        # Mach-O 64-bit: CF FA ED FE (LE) or CA FE BA BE (fat/universal)
        local magic
        magic=$(od -A n -N 4 -t x1 "$file" 2>/dev/null | tr -d ' \n')
        case "$magic" in
            cffaedfe|cefaedfe|cafebabe) return 0 ;;
        esac
        # Fallback: use `file` command if available
        if command -v file &>/dev/null; then
            file "$file" 2>/dev/null | grep -qiE "(mach-o|executable)" && return 0
        fi
        return 1
    else
        # Linux ELF: 7F 45 4C 46
        head -c 4 "$file" | grep -q "ELF" 2>/dev/null && return 0
        return 1
    fi
}

# Download binary
download_binary() {
    info "Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"

    info "Downloading Pulse client (${BINARY_NAME})..."
    local download_url="${GITHUB_REPO}/${BINARY_NAME}"

    if command -v curl &>/dev/null; then
        curl -sSL "$download_url" -o "$INSTALL_DIR/probe-client" || error "Failed to download binary"
    elif command -v wget &>/dev/null; then
        wget -q "$download_url" -O "$INSTALL_DIR/probe-client" || error "Failed to download binary"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi

    chmod +x "$INSTALL_DIR/probe-client"
    success "Downloaded and installed probe-client"
}

# ─── Linux: systemd service ───────────────────────────────────────────────────

create_service_linux() {
    info "Creating systemd service..."

    local env_lines=""
    env_lines+="Environment=\"AGENT_ID=$(systemd_escape_env "$AGENT_ID")\""$'\n'
    [ -n "$AGENT_NAME" ] && env_lines+="Environment=\"AGENT_NAME=$(systemd_escape_env "$AGENT_NAME")\""$'\n'
    env_lines+="Environment=\"SERVER_BASE=$(systemd_escape_env "$SERVER_BASE")\""$'\n'
    env_lines+="Environment=\"CLIENT_PORT=$(systemd_escape_env "$CLIENT_PORT")\""$'\n'
    [ -n "$SECRET" ]     && env_lines+="Environment=\"SECRET=$(systemd_escape_env "$SECRET")\""$'\n'

    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Pulse Monitoring Client
After=network.target

[Service]
Type=simple
$(printf '%s' "$env_lines")
ExecStart=${INSTALL_DIR}/probe-client
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pulse-client
LogRateLimitIntervalSec=30
LogRateLimitBurst=50

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
    success "systemd service created and started"
}

create_update_timer_linux() {
    info "Setting up auto-update timer (interval: ${UPDATE_INTERVAL})..."

    cat > /etc/systemd/system/${UPDATE_SERVICE_NAME}.service << EOF
[Unit]
Description=Pulse Client Auto-Update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/update.sh
Nice=19
IOSchedulingClass=idle
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pulse-update
LogRateLimitIntervalSec=60
LogRateLimitBurst=20
EOF

    cat > /etc/systemd/system/${UPDATE_SERVICE_NAME}.timer << EOF
[Unit]
Description=Pulse Client Auto-Update Timer

[Timer]
OnCalendar=${UPDATE_INTERVAL}
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable ${UPDATE_SERVICE_NAME}.timer
    systemctl start ${UPDATE_SERVICE_NAME}.timer
    success "Auto-update timer enabled (interval: ${UPDATE_INTERVAL})"
}

# ─── macOS: launchd daemon ────────────────────────────────────────────────────

create_service_macos() {
    info "Creating launchd daemon..."
    mkdir -p "$MACOS_PLIST_DIR"

    # Build EnvironmentVariables dict entries
    local env_xml=""
    env_xml+="        <key>AGENT_ID</key>"$'\n'"        <string>$(xml_escape "$AGENT_ID")</string>"$'\n'
    env_xml+="        <key>AGENT_NAME</key>"$'\n'"        <string>$(xml_escape "$AGENT_NAME")</string>"$'\n'
    env_xml+="        <key>SERVER_BASE</key>"$'\n'"        <string>$(xml_escape "$SERVER_BASE")</string>"$'\n'
    env_xml+="        <key>CLIENT_PORT</key>"$'\n'"        <string>$(xml_escape "$CLIENT_PORT")</string>"$'\n'
    [ -n "$SECRET" ] && env_xml+="        <key>SECRET</key>"$'\n'"        <string>$(xml_escape "$SECRET")</string>"$'\n'

    cat > "$MACOS_PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${MACOS_PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/probe-client</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
$(printf '%s' "$env_xml")    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/pulse-client.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/pulse-client-error.log</string>
</dict>
</plist>
EOF

    # Use bootstrap/bootout (modern API, required on macOS 11+)
    # bootout removes an existing registration so we can re-register cleanly
    launchctl bootout system/${MACOS_PLIST_LABEL} 2>/dev/null || true
    launchctl bootstrap system "$MACOS_PLIST_PATH"
    success "launchd daemon created and started"
}

# Convert UPDATE_INTERVAL keyword into a launchd StartCalendarInterval block
_macos_calendar_xml() {
    case "$UPDATE_INTERVAL" in
        hourly)
            echo "    <key>StartCalendarInterval</key>
    <dict>
        <key>Minute</key>
        <integer>0</integer>
    </dict>"
            ;;
        weekly)
            echo "    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key>
        <integer>1</integer>
        <key>Hour</key>
        <integer>3</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>"
            ;;
        *)  # daily (default)
            echo "    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>3</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>"
            ;;
    esac
}

create_update_timer_macos() {
    info "Setting up auto-update launchd timer (interval: ${UPDATE_INTERVAL})..."

    cat > "$MACOS_UPDATE_PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${MACOS_UPDATE_PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/update.sh</string>
    </array>
$(_macos_calendar_xml)
</dict>
</plist>
EOF

    launchctl bootout system/${MACOS_UPDATE_PLIST_LABEL} 2>/dev/null || true
    launchctl bootstrap system "$MACOS_UPDATE_PLIST_PATH"
    success "Auto-update launchd timer enabled (interval: ${UPDATE_INTERVAL})"
}

# ─── Auto-update script (embedded, handles both Linux and macOS) ──────────────

create_update_script() {
    info "Creating auto-update script..."

    cat > "${INSTALL_DIR}/update.sh" << 'UPDATEEOF'
#!/bin/bash
#
# Pulse Client Auto-Update Script (Linux + macOS)
#

INSTALL_DIR="/opt/pulse"
SERVICE_NAME="pulse-client"
GITHUB_REPO="https://raw.githubusercontent.com/xhhcn/Pulse/main/client"
CURRENT_BINARY="${INSTALL_DIR}/probe-client"
TEMP_BINARY="${INSTALL_DIR}/probe-client.tmp"
MACOS_PLIST_PATH="/Library/LaunchDaemons/com.pulse.client.plist"
MACOS_PLIST_LABEL="com.pulse.client"

log_msg() { echo "$(date '+%Y-%m-%d %H:%M:%S') $1"; }

detect_arch() {
    local os arch
    os=$(uname -s)
    arch=$(uname -m)
    case "${os}-${arch}" in
        Linux-x86_64|Linux-amd64)   echo "probe-client" ;;
        Linux-aarch64|Linux-arm64)  echo "probe-client-arm64" ;;
        Darwin-x86_64|Darwin-amd64) echo "probe-client-darwin-amd64" ;;
        Darwin-arm64|Darwin-aarch64) echo "probe-client-darwin-arm64" ;;
        *)
            log_msg "[ERROR] Unsupported OS/architecture: ${os}/${arch}"
            exit 1
            ;;
    esac
}

sha256_file() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "NOHASH_$(date +%s)"
    fi
}

validate_binary() {
    local file="$1"
    [ ! -s "$file" ] && return 1
    if [[ "$(uname -s)" == "Darwin" ]]; then
        local magic
        magic=$(od -A n -N 4 -t x1 "$file" 2>/dev/null | tr -d ' \n')
        case "$magic" in
            cffaedfe|cefaedfe|cafebabe) return 0 ;;
        esac
        command -v file &>/dev/null && file "$file" 2>/dev/null | grep -qiE "(mach-o|executable)" && return 0
        return 1
    else
        head -c 4 "$file" | grep -q "ELF" 2>/dev/null && return 0
        return 1
    fi
}

restart_service() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        # kickstart -k: kill the running process and restart it immediately.
        # If the service is not yet bootstrapped (first install via update script),
        # fall back to bootstrap.
        if launchctl print "system/${MACOS_PLIST_LABEL}" &>/dev/null 2>&1; then
            launchctl kickstart -k "system/${MACOS_PLIST_LABEL}"
            log_msg "[INFO] Updated and restarted ${MACOS_PLIST_LABEL}"
        elif [ -f "$MACOS_PLIST_PATH" ]; then
            launchctl bootstrap system "$MACOS_PLIST_PATH"
            log_msg "[INFO] Updated binary and bootstrapped ${MACOS_PLIST_LABEL}"
        else
            log_msg "[INFO] Updated binary, service plist not found"
        fi
    else
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            systemctl restart "$SERVICE_NAME"
            log_msg "[INFO] Updated and restarted ${SERVICE_NAME}"
        else
            log_msg "[INFO] Updated binary, service is not running"
        fi
    fi
}

cleanup() { rm -f "$TEMP_BINARY"; }
trap cleanup EXIT

main() {
    local binary_name
    binary_name=$(detect_arch)
    local download_url="${GITHUB_REPO}/${binary_name}"

    log_msg "[INFO] Checking for updates (${binary_name})..."

    if command -v curl &>/dev/null; then
        if ! curl -sSL --connect-timeout 15 --max-time 120 "$download_url" -o "$TEMP_BINARY" 2>/dev/null; then
            log_msg "[WARN] Download failed, will retry next cycle"
            exit 0
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --timeout=120 "$download_url" -O "$TEMP_BINARY" 2>/dev/null; then
            log_msg "[WARN] Download failed, will retry next cycle"
            exit 0
        fi
    else
        log_msg "[ERROR] Neither curl nor wget found"
        exit 1
    fi

    if ! validate_binary "$TEMP_BINARY"; then
        log_msg "[WARN] Downloaded file is not a valid binary, skipping update"
        exit 0
    fi

    if [ -f "$CURRENT_BINARY" ]; then
        local current_hash new_hash
        current_hash=$(sha256_file "$CURRENT_BINARY")
        new_hash=$(sha256_file "$TEMP_BINARY")

        if [ "$current_hash" = "$new_hash" ]; then
            log_msg "[INFO] Already up to date (hash: ${current_hash:0:12}...)"
            exit 0
        fi
        log_msg "[INFO] New version detected (${current_hash:0:12}... -> ${new_hash:0:12}...)"
    else
        log_msg "[INFO] No existing binary found, installing..."
    fi

    chmod +x "$TEMP_BINARY"
    mv -f "$TEMP_BINARY" "$CURRENT_BINARY"
    restart_service
}

main "$@"
UPDATEEOF

    chmod +x "${INSTALL_DIR}/update.sh"
    success "Auto-update script created: ${INSTALL_DIR}/update.sh"
}

# ─── Service / timer dispatch ─────────────────────────────────────────────────

create_service() {
    if [[ "$OS" == "Darwin" ]]; then
        create_service_macos
    else
        create_service_linux
    fi
}

create_update_timer() {
    if [[ "$OS" == "Darwin" ]]; then
        create_update_timer_macos
    else
        create_update_timer_linux
    fi
}

# ─── Status display ───────────────────────────────────────────────────────────

show_status() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Pulse Client Installed Successfully!           ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Configuration:"
    echo "  Agent ID:      $AGENT_ID"
    echo "  Agent Name:    $AGENT_NAME"
    echo "  Server:        $SERVER_BASE"
    echo "  Client Port:   $CLIENT_PORT"
    [ -n "$SECRET" ] && echo "  Secret:        ${SECRET:0:4}**** (hidden)"
    echo "  Install Dir:   $INSTALL_DIR"
    echo "  Auto-Update:   $([ "$AUTO_UPDATE" = true ] && echo "Enabled (${UPDATE_INTERVAL})" || echo "Disabled")"
    echo ""

    if [[ "$OS" == "Darwin" ]]; then
        echo "Service Commands (launchd):"
        echo "  Check status:   sudo launchctl print system/${MACOS_PLIST_LABEL}"
        echo "  View logs:      tail -f /var/log/pulse-client.log"
        echo "  Restart:        sudo launchctl kickstart -k system/${MACOS_PLIST_LABEL}"
        echo "  Stop:           sudo launchctl bootout system/${MACOS_PLIST_LABEL}"
        echo "  Start again:    sudo launchctl bootstrap system ${MACOS_PLIST_PATH}"
        if [ "$AUTO_UPDATE" = true ]; then
            echo ""
            echo "Auto-Update Commands:"
            echo "  Run now:        sudo launchctl kickstart system/${MACOS_UPDATE_PLIST_LABEL}"
            echo "  Update logs:    tail -f /var/log/pulse-client.log"
            echo "  Disable:        sudo launchctl bootout system/${MACOS_UPDATE_PLIST_LABEL} && sudo rm -f ${MACOS_UPDATE_PLIST_PATH}"
        fi
        echo ""
        echo "Uninstall:"
        if [ "$AUTO_UPDATE" = true ]; then
            echo "  sudo launchctl bootout system/${MACOS_PLIST_LABEL} 2>/dev/null || true"
            echo "  sudo launchctl bootout system/${MACOS_UPDATE_PLIST_LABEL} 2>/dev/null || true"
            echo "  sudo rm -rf ${INSTALL_DIR} ${MACOS_PLIST_PATH} ${MACOS_UPDATE_PLIST_PATH}"
        else
            echo "  sudo launchctl bootout system/${MACOS_PLIST_LABEL} 2>/dev/null || true"
            echo "  sudo rm -rf ${INSTALL_DIR} ${MACOS_PLIST_PATH}"
        fi
    else
        echo "Service Commands (systemd):"
        echo "  Check status:   systemctl status ${SERVICE_NAME}"
        echo "  View logs:      journalctl -u ${SERVICE_NAME} -f"
        echo "  View all logs:  journalctl -u ${SERVICE_NAME} --no-pager -n 100"
        echo "  Restart:        systemctl restart ${SERVICE_NAME}"
        echo "  Stop:           systemctl stop ${SERVICE_NAME}"
        if [ "$AUTO_UPDATE" = true ]; then
            echo ""
            echo "Auto-Update Commands:"
            echo "  Check timer:    systemctl list-timers ${UPDATE_SERVICE_NAME}.timer"
            echo "  Update now:     systemctl start ${UPDATE_SERVICE_NAME}.service"
            echo "  Update logs:    journalctl -u ${UPDATE_SERVICE_NAME} --no-pager -n 50"
            echo "  Disable:        systemctl stop ${UPDATE_SERVICE_NAME}.timer && systemctl disable ${UPDATE_SERVICE_NAME}.timer"
        fi
        echo ""
        echo "Uninstall:"
        if [ "$AUTO_UPDATE" = true ]; then
            echo "  systemctl stop ${SERVICE_NAME} ${UPDATE_SERVICE_NAME}.timer && \\"
            echo "  systemctl disable ${SERVICE_NAME} ${UPDATE_SERVICE_NAME}.timer && \\"
            echo "  rm -rf ${INSTALL_DIR} /etc/systemd/system/${SERVICE_NAME}.service \\"
            echo "  /etc/systemd/system/${UPDATE_SERVICE_NAME}.service \\"
            echo "  /etc/systemd/system/${UPDATE_SERVICE_NAME}.timer && \\"
            echo "  systemctl daemon-reload"
        else
            echo "  systemctl stop ${SERVICE_NAME} && systemctl disable ${SERVICE_NAME} && \\"
            echo "  rm -rf ${INSTALL_DIR} /etc/systemd/system/${SERVICE_NAME}.service && \\"
            echo "  systemctl daemon-reload"
        fi
    fi
    echo ""
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    print_banner
    parse_args "$@"
    check_root
    prompt_values

    # Verify this OS is supported
    case "$OS" in
        Linux|Darwin) ;;
        *) error "Unsupported OS: $OS (only Linux and macOS are supported)" ;;
    esac

    detect_arch
    validate_config_values
    download_binary
    create_service

    if [ "$AUTO_UPDATE" = true ]; then
        create_update_script
        create_update_timer
    fi

    show_status
}

main "$@"
