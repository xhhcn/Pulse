#!/bin/bash

# Pulse Server Standalone Installation Script
# This script installs Pulse Server as a standalone binary with systemd service

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/pulse"
SERVICE_NAME="pulse-server"
GITHUB_REPO="xhhcn/Pulse"
VERSION="latest"  # Can be changed to specific version like "v1.2.3"

# Print colored message
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_message "$RED" "❌ Please run as root (use sudo)"
    exit 1
fi

print_message "$GREEN" "🚀 Starting Pulse Server installation..."

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        BINARY_NAME="pulse-server-standalone-linux-amd64"
        ;;
    aarch64|arm64)
        BINARY_NAME="pulse-server-standalone-linux-arm64"
        ;;
    *)
        print_message "$RED" "❌ Unsupported architecture: $ARCH"
        print_message "$YELLOW" "   Supported: x86_64, aarch64/arm64"
        exit 1
        ;;
esac

print_message "$GREEN" "✅ Detected architecture: $ARCH"
print_message "$GREEN" "📦 Binary: $BINARY_NAME"

# Create installation directory
print_message "$YELLOW" "📁 Creating installation directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/data"

# Download binary
print_message "$YELLOW" "⬇️  Downloading Pulse Server..."
if [ "$VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/$GITHUB_REPO/releases/latest/download/$BINARY_NAME"
else
    DOWNLOAD_URL="https://github.com/$GITHUB_REPO/releases/download/$VERSION/$BINARY_NAME"
fi

# Download next to the installed binary and swap it in: writing over a
# running executable fails with "Text file busy", so an in-place upgrade
# used to abort here.
if ! wget -q --show-progress "$DOWNLOAD_URL" -O "$INSTALL_DIR/pulse-server.new"; then
    rm -f "$INSTALL_DIR/pulse-server.new"
    print_message "$RED" "❌ Failed to download binary"
    print_message "$YELLOW" "   URL: $DOWNLOAD_URL"
    exit 1
fi

chmod +x "$INSTALL_DIR/pulse-server.new"
if [ -f "$INSTALL_DIR/pulse-server" ]; then
    cp -f "$INSTALL_DIR/pulse-server" "$INSTALL_DIR/pulse-server.bak"
fi
mv -f "$INSTALL_DIR/pulse-server.new" "$INSTALL_DIR/pulse-server"
print_message "$GREEN" "✅ Binary downloaded and made executable"

# Drop the migration helper scripts (backup / restore / migrate) into
# $INSTALL_DIR/scripts so future migrations are a single command on a
# fresh VPS — no git clone required. We fetch from the same tag as the
# binary so the scripts and the server agree about the /api/admin/backup
# contract. If GitHub is unreachable we don't hard-fail the install;
# the server itself is already working and the scripts can be fetched
# later by rerunning the installer.
print_message "$YELLOW" "📂 Installing migration helper scripts..."
mkdir -p "$INSTALL_DIR/scripts"
if [ "$VERSION" = "latest" ]; then
    SCRIPT_BASE="https://raw.githubusercontent.com/$GITHUB_REPO/main/scripts"
else
    SCRIPT_BASE="https://raw.githubusercontent.com/$GITHUB_REPO/$VERSION/scripts"
fi
SCRIPTS_OK=true
for s in backup.sh restore.sh migrate.sh; do
    if ! wget -q "$SCRIPT_BASE/$s" -O "$INSTALL_DIR/scripts/$s"; then
        SCRIPTS_OK=false
        break
    fi
    chmod +x "$INSTALL_DIR/scripts/$s"
done
if $SCRIPTS_OK; then
    ln -sf "$INSTALL_DIR/scripts/migrate.sh" /usr/local/bin/pulse-migrate
    ln -sf "$INSTALL_DIR/scripts/backup.sh"  /usr/local/bin/pulse-backup
    ln -sf "$INSTALL_DIR/scripts/restore.sh" /usr/local/bin/pulse-restore
    print_message "$GREEN" "✅ Migration helpers installed to $INSTALL_DIR/scripts"
    print_message "$GREEN" "   CLI shortcuts: pulse-migrate / pulse-backup / pulse-restore"
else
    rm -f "$INSTALL_DIR/scripts/backup.sh" "$INSTALL_DIR/scripts/restore.sh" "$INSTALL_DIR/scripts/migrate.sh"
    print_message "$YELLOW" "⚠️  Could not fetch migration helpers (non-fatal) — rerun installer later."
fi

# Create systemd service
print_message "$YELLOW" "⚙️  Creating systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Pulse Server Monitor (Standalone)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/pulse-server
Restart=always
RestartSec=5
Environment="PORT=8008"
# Log to systemd journal (auto-managed)
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pulse-server

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload
print_message "$GREEN" "✅ Systemd service created"

# Start (or restart, when upgrading a running install) the service
print_message "$YELLOW" "🚀 Starting Pulse Server..."
systemctl restart $SERVICE_NAME
systemctl enable $SERVICE_NAME

# Wait a moment for service to start
sleep 2

# Check service status
if systemctl is-active --quiet $SERVICE_NAME; then
    print_message "$GREEN" "✅ Pulse Server is running!"
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    print_message "$GREEN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    print_message "$GREEN" "🎉 Installation completed successfully!"
    print_message "$GREEN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    print_message "$YELLOW" "📍 Access your dashboard:"
    print_message "$GREEN" "   http://$SERVER_IP:8008"
    print_message "$GREEN" "   http://localhost:8008 (if local)"
    echo ""
    print_message "$YELLOW" "🔧 Useful commands:"
    print_message "$GREEN" "   sudo systemctl status $SERVICE_NAME   # Check status"
    print_message "$GREEN" "   sudo systemctl stop $SERVICE_NAME     # Stop service"
    print_message "$GREEN" "   sudo systemctl restart $SERVICE_NAME  # Restart service"
    print_message "$GREEN" "   sudo journalctl -u $SERVICE_NAME -f   # View logs (live)"
    echo ""
    print_message "$YELLOW" "📁 Installation directory: $INSTALL_DIR"
    print_message "$YELLOW" "💾 Data directory: $INSTALL_DIR/data"
    echo ""
    print_message "$YELLOW" "🔄 Migrate from another Pulse server (zero downtime):"
    print_message "$GREEN" "   sudo pulse-migrate --from https://OLD_HOST:8008"
    echo ""
    print_message "$YELLOW" "🗑️  Uninstall:"
    print_message "$GREEN" "   sudo systemctl stop $SERVICE_NAME && sudo systemctl disable $SERVICE_NAME"
    print_message "$GREEN" "   sudo rm -f $INSTALL_DIR/pulse-server /etc/systemd/system/$SERVICE_NAME.service"
    print_message "$GREEN" "   sudo rm -f /usr/local/bin/pulse-migrate /usr/local/bin/pulse-backup /usr/local/bin/pulse-restore"
    print_message "$GREEN" "   sudo rm -rf $INSTALL_DIR/scripts $INSTALL_DIR/data && sudo systemctl daemon-reload"
    echo ""
    print_message "$GREEN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    print_message "$RED" "❌ Failed to start Pulse Server"
    print_message "$YELLOW" "   Check logs: sudo journalctl -u $SERVICE_NAME -n 50"
    exit 1
fi

