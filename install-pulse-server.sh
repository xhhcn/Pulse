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

if ! wget -q --show-progress "$DOWNLOAD_URL" -O "$INSTALL_DIR/pulse-server"; then
    print_message "$RED" "❌ Failed to download binary"
    print_message "$YELLOW" "   URL: $DOWNLOAD_URL"
    exit 1
fi

chmod +x "$INSTALL_DIR/pulse-server"
print_message "$GREEN" "✅ Binary downloaded and made executable"

# Create log directory first
print_message "$YELLOW" "📁 Creating log directory..."
mkdir -p /var/log/pulse-server
chmod 750 /var/log/pulse-server

# Configure log rotation
print_message "$YELLOW" "📝 Configuring log rotation..."
cat > /etc/logrotate.d/$SERVICE_NAME << 'EOF'
/var/log/pulse-server/*.log {
    daily
    rotate 14
    maxsize 100M
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
if logrotate -d /etc/logrotate.d/$SERVICE_NAME >/dev/null 2>&1; then
    print_message "$GREEN" "✅ Log rotation configured (max 100MB per file, 14 days retention)"
else
    print_message "$YELLOW" "⚠️  Log rotation config created but validation failed (non-critical)"
fi

# Create systemd service with log management
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
# Log configuration - redirect to file for logrotate management
StandardOutput=append:/var/log/pulse-server/pulse-server.log
StandardError=append:/var/log/pulse-server/pulse-server.log
# Also send to journal for systemctl status
SyslogIdentifier=pulse-server

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload
print_message "$GREEN" "✅ Systemd service created with log management"

# Start service
print_message "$YELLOW" "🚀 Starting Pulse Server..."
systemctl start $SERVICE_NAME
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
    print_message "$GREEN" "   sudo tail -f /var/log/pulse-server/pulse-server.log  # View logs (live)"
    print_message "$GREEN" "   sudo du -sh /var/log/pulse-server/    # Check log size"
    echo ""
    print_message "$YELLOW" "📁 Installation directory: $INSTALL_DIR"
    print_message "$YELLOW" "💾 Data directory: $INSTALL_DIR/data"
    print_message "$YELLOW" "📝 Log management:"
    print_message "$GREEN" "   Logs are auto-rotated: 100MB per file, 14 daily rotations (max ~1.4GB total)"
    print_message "$GREEN" "   Location: /var/log/pulse-server/pulse-server.log"
    print_message "$GREEN" "   Rotated logs: /var/log/pulse-server/pulse-server.log.*.gz"
    echo ""
    print_message "$YELLOW" "🗑️  Uninstall:"
    print_message "$GREEN" "   sudo systemctl stop $SERVICE_NAME && sudo systemctl disable $SERVICE_NAME"
    print_message "$GREEN" "   sudo rm -f $INSTALL_DIR/pulse-server /etc/systemd/system/$SERVICE_NAME.service"
    print_message "$GREEN" "   sudo rm -f /etc/logrotate.d/$SERVICE_NAME"
    print_message "$GREEN" "   sudo rm -rf $INSTALL_DIR/data /var/log/pulse-server && sudo systemctl daemon-reload"
    echo ""
    print_message "$GREEN" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    print_message "$RED" "❌ Failed to start Pulse Server"
    print_message "$YELLOW" "   Check logs: sudo journalctl -u $SERVICE_NAME -n 50"
    exit 1
fi

