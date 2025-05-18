#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Runegate Uninstallation Script for Debian-based systems
# This script will:
# 1. Stop and disable the systemd service
# 2. Remove service files
# 3. Optionally remove configuration and data files

set -e

# Must be run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Print banner
echo "============================================="
echo "     Runegate Uninstallation Script"
echo "============================================="
echo ""

# Configuration variables
RUNEGATE_USER="runegate"
RUNEGATE_GROUP="runegate"
INSTALL_DIR="/opt/runegate"
CONFIG_DIR="/etc/runegate"
LOG_DIR="/var/log/runegate"
DATA_DIR="/var/lib/runegate"

# Ask for confirmation of data removal
read -p "Remove configuration and data files? [y/N] " -n 1 -r REMOVE_DATA
echo ""

# Stop and disable service if running
if systemctl is-active --quiet runegate; then
    echo "Stopping runegate service..."
    systemctl stop runegate
fi

if systemctl is-enabled --quiet runegate; then
    echo "Disabling runegate service..."
    systemctl disable runegate
fi

# Remove service file
echo "Removing systemd service file..."
rm -f /etc/systemd/system/runegate.service
systemctl daemon-reload

# Remove binary and installation files
echo "Removing Runegate installation..."
rm -rf "$INSTALL_DIR"

# Remove configuration and data files if requested
if [[ $REMOVE_DATA =~ ^[Yy]$ ]]; then
    echo "Removing configuration and data files..."
    rm -rf "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    
    # Ask if we should remove the user and group
    read -p "Remove runegate user and group? [y/N] " -n 1 -r REMOVE_USER
    echo ""
    
    if [[ $REMOVE_USER =~ ^[Yy]$ ]]; then
        echo "Removing runegate user and group..."
        if getent passwd "$RUNEGATE_USER" > /dev/null; then
            userdel "$RUNEGATE_USER"
        fi
        
        if getent group "$RUNEGATE_GROUP" > /dev/null; then
            groupdel "$RUNEGATE_GROUP"
        fi
    fi
else
    echo "Keeping configuration and data files at:"
    echo "  - $CONFIG_DIR"
    echo "  - $LOG_DIR"
    echo "  - $DATA_DIR"
fi

echo "============================================="
echo "Uninstallation Complete!"
echo "============================================="
