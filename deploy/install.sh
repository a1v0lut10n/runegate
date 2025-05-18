#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Runegate Installation Script for Debian-based systems
# This script will:
# 1. Install required dependencies
# 2. Create a runegate user
# 3. Build and install the Runegate binary
# 4. Set up configuration files with proper permissions
# 5. Configure the systemd service
# 6. Start the service

set -e

# Must be run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Print banner
echo "============================================="
echo "       Runegate Deployment Script"
echo "============================================="
echo ""

# Configuration variables
RUNEGATE_USER="runegate"
RUNEGATE_GROUP="runegate"
INSTALL_DIR="/opt/runegate"
CONFIG_DIR="/etc/runegate"
LOG_DIR="/var/log/runegate"
DATA_DIR="/var/lib/runegate"
REPO_DIR="$(pwd)"

# Check if this script is run from the repository root
if [ ! -f "$REPO_DIR/Cargo.toml" ] || [ ! -d "$REPO_DIR/src" ]; then
    echo "Error: This script must be run from the Runegate repository root" >&2
    exit 1
fi

echo "Step 1: Installing required dependencies..."
apt-get update
apt-get install -y curl build-essential pkg-config libssl-dev

# Install Rust if not already installed
if ! command -v rustc &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

echo "Step 2: Creating runegate user and group..."
if ! getent group "$RUNEGATE_GROUP" > /dev/null; then
    groupadd --system "$RUNEGATE_GROUP"
fi

if ! getent passwd "$RUNEGATE_USER" > /dev/null; then
    useradd --system --gid "$RUNEGATE_GROUP" --shell /bin/false --home-dir "$INSTALL_DIR" "$RUNEGATE_USER"
fi

echo "Step 3: Creating directory structure..."
# Create required directories
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR"

echo "Step 4: Building Runegate application..."
# Build the application
cargo build --release

echo "Step 5: Installing Runegate application..."
# Copy binary to install location
cp "$REPO_DIR/target/release/runegate" "$INSTALL_DIR/bin/"
chmod 755 "$INSTALL_DIR/bin/runegate"

# Copy static files and templates
if [ -d "$REPO_DIR/static" ]; then
    mkdir -p "$INSTALL_DIR/static"
    cp -r "$REPO_DIR/static/"* "$INSTALL_DIR/static/"
fi

# Create configuration files
if [ -f "$REPO_DIR/.env.example" ]; then
    cp "$REPO_DIR/.env.example" "$CONFIG_DIR/runegate.env"
    echo "# Copied from .env.example - Modify for your environment" > "$CONFIG_DIR/runegate.env"
    cat "$REPO_DIR/.env.example" >> "$CONFIG_DIR/runegate.env"
    
    # Generate secure secrets and update the environment file
    echo "Generating secure secrets for JWT and session..."
    "$REPO_DIR/deploy/generate_secrets.sh" "$CONFIG_DIR/runegate.env"
fi

# Copy email configuration example
if [ -f "$REPO_DIR/config/email.toml.example" ]; then
    mkdir -p "$CONFIG_DIR/config"
    cp "$REPO_DIR/config/email.toml.example" "$CONFIG_DIR/config/email.toml"
fi

echo "Step 6: Setting correct permissions..."
# Set proper ownership and permissions
chown -R "$RUNEGATE_USER:$RUNEGATE_GROUP" "$INSTALL_DIR"
chown -R "$RUNEGATE_USER:$RUNEGATE_GROUP" "$CONFIG_DIR"
chown -R "$RUNEGATE_USER:$RUNEGATE_GROUP" "$LOG_DIR"
chown -R "$RUNEGATE_USER:$RUNEGATE_GROUP" "$DATA_DIR"

# Make config files secure
chmod 750 "$CONFIG_DIR"
chmod 640 "$CONFIG_DIR/runegate.env"
if [ -f "$CONFIG_DIR/config/email.toml" ]; then
    chmod 640 "$CONFIG_DIR/config/email.toml"
fi

echo "Step 7: Installing systemd service..."
# Copy systemd service file
cp "$REPO_DIR/deploy/systemd/runegate.service" /etc/systemd/system/

# Reload systemd to recognize the new service
systemctl daemon-reload

echo "============================================="
echo "Installation Complete!"
echo "============================================="
echo ""
echo "The Runegate service has been installed but not started."
echo ""
echo "IMPORTANT: Before starting the service:"
echo "1. Edit the configuration file: $CONFIG_DIR/runegate.env"
echo "2. Configure your email settings: $CONFIG_DIR/config/email.toml"
echo ""
echo "Then, start and enable the service with:"
echo "  systemctl start runegate"
echo "  systemctl enable runegate"
echo ""
echo "To check service status:"
echo "  systemctl status runegate"
echo ""
echo "To view logs:"
echo "  journalctl -u runegate -f"
echo "============================================="
