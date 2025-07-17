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
- OpenSSL (for secure secret generation)

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

   > **Important**: The email configuration path must be at `/etc/runegate/config/email.toml`. This is the path the application checks in production deployments.

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

### Managing Secure Secrets

Runegate requires two secure secrets for operation:

1. **JWT Secret** - Used for signing magic link tokens
2. **Session Key** - Used for encrypting session cookies

The installation script automatically generates these secrets using cryptographically secure random values. However, you can also manage these secrets manually:

#### Generating New Secrets

```bash
# Generate and show secrets only
sudo ./deploy/generate_secrets.sh

# Generate and update an environment file
sudo ./deploy/generate_secrets.sh /etc/runegate/runegate.env
```

#### Manual Secret Generation

If you prefer to generate secrets manually:

```bash
# Generate JWT secret
openssl rand -base64 64 | tr -d '\n'

# Generate session key
openssl rand -base64 32 | tr -d '\n'
```

#### Important Security Notes

- Always use secrets with high entropy (at least 256 bits)
- Store secrets securely and avoid committing them to version control
- Rotate secrets periodically in production environments
- If secrets are compromised, generate new ones immediately

## Nginx Configuration

Starting with version 0.1.2, Runegate includes an optional nginx configuration setup. This is particularly useful when you want to:

- Serve Runegate under a specific path prefix (e.g., `/auth/` or `/runegate/`)
- Enable SSL/TLS termination
- Use nginx as a reverse proxy in front of Runegate

### Installation Script Integration

By default, the installation script will not set up nginx configuration, as Runegate is typically integrated into an existing web server configuration.

If you want to set up a standalone nginx configuration for Runegate, you can use the `--setup-nginx` flag:

```bash
sudo ./deploy/install.sh --setup-nginx
```

This will:

- Copy the Runegate nginx configuration to `/etc/nginx/sites-available/`
- Enable the site by creating a symlink in `/etc/nginx/sites-enabled/`
- Test the nginx configuration
- Provide instructions for reloading nginx

### Manual Setup

1. Copy the template configuration:

   ```bash
   sudo cp /opt/runegate/deploy/nginx/runegate.conf /etc/nginx/sites-available/
   ```

2. Edit the configuration to suit your needs:

   ```bash
   sudo nano /etc/nginx/sites-available/runegate.conf
   ```

   > **Important**: Update the `server_name` directive and adjust any other settings as needed.

3. Enable the site:

   ```bash
   sudo ln -s /etc/nginx/sites-available/runegate.conf /etc/nginx/sites-enabled/
   ```

4. Test and reload nginx:

   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

### Path Prefix Configuration

If you want to serve Runegate under a specific path prefix (e.g., `/auth/`), modify your nginx configuration:

```nginx
# Example for serving Runegate under /auth/ path
location /auth/ {
    proxy_pass http://127.0.0.1:7870/;
    
    # Standard headers
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # Fix redirects - important!
    proxy_redirect / /auth/;
}
```

> **Note**: Runegate 0.1.1+ automatically detects when it's running behind a proxy with a path prefix and adjusts API calls accordingly. No additional configuration is needed.

## Security Best Practices

1. Always run Runegate with the dedicated `runegate` user (automatic with systemd)
2. Secure your JWT secret and session key
3. Set up SSL/TLS termination with nginx in production environments
4. Review the systemd hardening parameters in `runegate.service`
5. Implement a firewall (ufw) and only expose necessary ports
