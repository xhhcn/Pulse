#!/bin/bash
#
# Pulse Client Installation Script for Linux
# Usage: curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | bash -s -- --id YOUR_ID --server http://YOUR_SERVER:8080
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INSTALL_DIR="/opt/pulse"
SERVICE_NAME="pulse-client"
GITHUB_REPO="https://raw.githubusercontent.com/xhhcn/Pulse/main/client"
CLIENT_PORT="9090"
AGENT_NAME=""
SECRET=""

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
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
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
    echo "Options:"
    echo "  --id ID          Agent ID (required, must match server config)"
    echo "  --name NAME      Agent display name (optional, defaults to ID)"
    echo "  --server URL     Server base URL (required, e.g., http://your-server:8080)"
    echo "  --port PORT      Client port (optional, default: 9090)"
    echo "  --secret SECRET  Secret for authentication (optional, if server requires it)"
    echo "  --help, -h       Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --id my-server-1 --server http://monitor.example.com:8080 --secret my-secret"
    echo ""
    echo "Or using curl:"
    echo "  curl -sSL https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.sh | sudo bash -s -- --id my-server-1 --server http://monitor.example.com:8080 --secret my-secret"
}

# Prompt for required values if not provided
prompt_values() {
    if [ -z "$AGENT_ID" ]; then
        read -p "Enter Agent ID (must match server config): " AGENT_ID
        [ -z "$AGENT_ID" ] && error "Agent ID is required"
    fi
    
    if [ -z "$SERVER_BASE" ]; then
        read -p "Enter Server URL (e.g., http://your-server:8080): " SERVER_BASE
        [ -z "$SERVER_BASE" ] && error "Server URL is required"
    fi
    
    if [ -z "$AGENT_NAME" ]; then
        AGENT_NAME="$AGENT_ID"
    fi
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            BINARY_NAME="probe-client"
            ;;
        aarch64|arm64)
            BINARY_NAME="probe-client-arm64"
            ;;
        *)
            error "Unsupported architecture: $ARCH"
            ;;
    esac
    info "Detected architecture: $ARCH"
}

# Download binary
download_binary() {
    info "Creating installation directory: $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    
    info "Downloading Pulse client..."
    DOWNLOAD_URL="${GITHUB_REPO}/${BINARY_NAME}"
    
    if command -v curl &> /dev/null; then
        curl -sSL "$DOWNLOAD_URL" -o "$INSTALL_DIR/probe-client" || error "Failed to download binary"
    elif command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O "$INSTALL_DIR/probe-client" || error "Failed to download binary"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi
    
    chmod +x "$INSTALL_DIR/probe-client"
    success "Downloaded and installed probe-client"
}

# Configure log rotation
configure_logrotate() {
    info "Configuring log rotation..."
    
    # Create logrotate configuration
    cat > /etc/logrotate.d/${SERVICE_NAME} << 'EOF'
/var/log/pulse-client/*.log {
    daily
    rotate 7
    maxsize 50M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 root root
    sharedscripts
}
EOF
    
    # Test logrotate configuration
    if logrotate -d /etc/logrotate.d/${SERVICE_NAME} >/dev/null 2>&1; then
        success "Log rotation configured (max 50MB per file, 7 days retention)"
    else
        warn "Log rotation config created but validation failed (non-critical)"
    fi
}

# Create systemd service
create_service() {
    info "Creating systemd service..."
    
    # Create log directory with proper permissions
    mkdir -p /var/log/pulse-client
    chmod 750 /var/log/pulse-client
    
    # Build environment variables for systemd service
    ENV_LINES="Environment=\"AGENT_ID=${AGENT_ID}\"\n"
    if [ -n "$AGENT_NAME" ]; then
        ENV_LINES="${ENV_LINES}Environment=\"AGENT_NAME=${AGENT_NAME}\"\n"
    fi
    ENV_LINES="${ENV_LINES}Environment=\"SERVER_BASE=${SERVER_BASE}\"\n"
    ENV_LINES="${ENV_LINES}Environment=\"CLIENT_PORT=${CLIENT_PORT}\"\n"
    if [ -n "$SECRET" ]; then
        ENV_LINES="${ENV_LINES}Environment=\"SECRET=${SECRET}\"\n"
    fi
    
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=Pulse Monitoring Client
After=network.target

[Service]
Type=simple
$(echo -e "$ENV_LINES")
ExecStart=${INSTALL_DIR}/probe-client
Restart=always
RestartSec=10
# Log configuration - redirect to file for logrotate management
StandardOutput=append:/var/log/pulse-client/pulse-client.log
StandardError=append:/var/log/pulse-client/pulse-client.log
# Also send to journal for systemctl status
SyslogIdentifier=pulse-client

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
    
    configure_logrotate
    
    success "Service created and started with log rotation"
}

# Show status
show_status() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}            Pulse Client Installed Successfully!           ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Configuration:"
    echo "  Agent ID:    $AGENT_ID"
    echo "  Server:      $SERVER_BASE"
    echo "  Client Port: $CLIENT_PORT"
    if [ -n "$SECRET" ]; then
        echo "  Secret:      ${SECRET:0:4}**** (hidden)"
    fi
    echo "  Install Dir: $INSTALL_DIR"
    echo ""
    echo "Service Commands:"
    echo "  Check status:   systemctl status ${SERVICE_NAME}"
    echo "  View logs:      tail -f /var/log/pulse-client/pulse-client.log"
    echo "  View all logs:  less /var/log/pulse-client/pulse-client.log"
    echo "  Restart:        systemctl restart ${SERVICE_NAME}"
    echo "  Stop:           systemctl stop ${SERVICE_NAME}"
    echo "  Uninstall:      systemctl stop ${SERVICE_NAME} && systemctl disable ${SERVICE_NAME} && rm -f ${INSTALL_DIR}/probe-client /etc/systemd/system/${SERVICE_NAME}.service /etc/logrotate.d/${SERVICE_NAME} && rm -rf /var/log/pulse-client && systemctl daemon-reload"
    echo ""
    echo "Log Management:"
    echo "  Logs are auto-rotated: 50MB per file, 7 daily rotations (max ~350MB total)"
    echo "  Location:       /var/log/pulse-client/pulse-client.log"
    echo "  Rotated logs:   /var/log/pulse-client/pulse-client.log.*.gz"
    echo "  View live:      tail -f /var/log/pulse-client/pulse-client.log"
    echo ""
}

# Main
main() {
    print_banner
    parse_args "$@"
    check_root
    prompt_values
    detect_arch
    download_binary
    create_service
    show_status
}

main "$@"

