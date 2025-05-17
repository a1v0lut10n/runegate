# Runegate Deployment Guide

This directory contains scripts and configuration files to deploy Runegate as a systemd service on Debian-based systems (Ubuntu, Debian, etc.).

## Features of this Deployment System

- 🔒 Creates a dedicated low-privilege `runegate` user
- 🚀 Automatic installation of all dependencies
- 📁 Standard Linux directory structure (`/opt/runegate`, `/etc/runegate`, etc.)
- ⚙️ Secure configuration file management with proper permissions
- 🔄 Systemd service with auto-restart capabilities
- 📊 Integrated with system journal for logging
- 🛡️ Hardened systemd service with security features:
  - `ProtectSystem=strict` - Prevents writing to system directories
  - `ProtectHome=true` - No access to user home directories
  - `PrivateTmp=true` - Private /tmp directory
  - `NoNewPrivileges=true` - Prevents privilege escalation
  - Memory limits to prevent resource exhaustion

## Directory Structure After Installation

```bash
/opt/runegate/         # Installation directory
├── bin/
│   └── runegate       # The Runegate binary
└── static/            # Static files (login page, etc.)

/etc/runegate/         # Configuration directory
├── runegate.env       # Environment variables
└── config/
    └── email.toml     # Email configuration

/var/log/runegate/     # Log directory
/var/lib/runegate/     # Data directory (for future use)
```

## Installation Instructions

### Prerequisites

- Debian-based system (Ubuntu 20.04+, Debian 10+)
- Root or sudo access
- Internet connection for dependency installation

### Installation Steps

1. Clone the repository:

   ```bash
   git clone https://github.com/a1v0lut10n/runegate.git
   cd runegate
   ```

2. Run the installation script as root:

   ```bash
   sudo ./deploy/install.sh
   ```

3. Configure Runegate:

   ```bash
   sudo nano /etc/runegate/runegate.env
   sudo nano /etc/runegate/config/email.toml
   ```

4. Start and enable the service:

   ```bash
   sudo systemctl start runegate
   sudo systemctl enable runegate
   ```

5. Check the status:

   ```bash
   sudo systemctl status runegate
   ```

### Viewing Logs

```bash
# View recent logs
sudo journalctl -u runegate -n 50

# Follow logs in real-time
sudo journalctl -u runegate -f

# View logs since a specific time
sudo journalctl -u runegate --since "1 hour ago"

# View logs within a specific date range
sudo journalctl -u runegate --since "2025-05-17" --until "2025-05-18"
```

## Managing the Service

```bash
# Start the service
sudo systemctl start runegate

# Stop the service
sudo systemctl stop runegate

# Restart the service
sudo systemctl restart runegate

# Check service status
sudo systemctl status runegate

# Enable automatic start at boot
sudo systemctl enable runegate

# Disable automatic start
sudo systemctl disable runegate
```

## Updating Runegate

To update Runegate to a newer version:

1. Stop the service:

   ```bash
   sudo systemctl stop runegate
   ```

2. Pull the latest code:

   ```bash
   cd /path/to/runegate/repo
   git pull
   ```

3. Re-run the installation script:

   ```bash
   sudo ./deploy/install.sh
   ```

4. Start the service:

   ```bash
   sudo systemctl start runegate
   ```

## Uninstallation

To uninstall Runegate:

```bash
sudo ./deploy/uninstall.sh
```

This script will:

1. Stop and disable the service
2. Remove the systemd service file
3. Optionally remove configuration files and the dedicated user

## Troubleshooting

### Service Fails to Start

Check logs for detailed error messages:

```bash
sudo journalctl -u runegate -n 50
```

Common issues:

- Incorrect permission on configuration files
- Missing environment variables
- Email configuration issues

### Port Binding Issues

If Runegate fails with "address already in use":

```bash
# Find which process is using the port
sudo netstat -tuln | grep 7870
sudo lsof -i :7870
```

## Security Best Practices

1. Always run Runegate with the dedicated `runegate` user (automatic with systemd)
2. Secure your JWT secret and session key
3. Consider setting up a proper SSL/TLS termination with nginx/apache in front
4. Review the systemd hardening parameters in `runegate.service`
5. Implement a firewall (ufw) and only expose necessary ports
