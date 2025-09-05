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

Runegate ships with an optional nginx reference configuration to place nginx in front of Runegate for TLS termination and reverse proxying. Recommended deployment is a dedicated subdomain (e.g., `app.example.com`) rather than a path prefix.

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

### HTTPS and SSL Configuration

When using Runegate in production with SSL/TLS:

1. Terminate TLS at nginx with valid certificates (e.g., Let’s Encrypt).
2. Redirect HTTP (port 80) to HTTPS (port 443) and proxy only on 443.
3. Set `RUNEGATE_BASE_URL=https://your-domain.com` so magic links use the public HTTPS URL.
4. Keep `RUNEGATE_COOKIE_DOMAIN` unset unless you need cross-subdomain cookies.
5. Restart Runegate after environment changes.

### Manual Setup

1. Copy the template configuration:

   ```bash
   sudo cp /opt/runegate/deploy/nginx/runegate-nginx.conf /etc/nginx/sites-available/
   ```

2. Edit the configuration to suit your needs:

   ```bash
   sudo nano /etc/nginx/sites-available/runegate-nginx.conf
   ```

   > **Important**: Update the `server_name` directive and adjust any other settings as needed.

3. Enable the site:

   ```bash
   sudo ln -s /etc/nginx/sites-available/runegate-nginx.conf /etc/nginx/sites-enabled/
   ```

4. Test and reload nginx:

   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

### Path Prefixes (Not Recommended)

Runegate is designed to sit at the root of a dedicated subdomain (e.g., `app.example.com`). Path-prefix deployments (e.g., `example.com/app`) complicate cookie scoping and redirects and are not supported by default. Prefer a subdomain and host-only cookies for the most reliable behavior.

If you must use a path prefix, you will need to handle cookie scope, redirects, and proxy path rewriting carefully. This is outside the scope of the provided templates.

## Security Best Practices

1. Always run Runegate with the dedicated `runegate` user (automatic with systemd)
2. Secure your JWT secret and session key
3. Set up SSL/TLS termination with nginx in production environments
4. Review the systemd hardening parameters in `runegate.service`
5. Implement a firewall (ufw) and only expose necessary ports

## Migration Notes: nginx config rename

If you previously installed the nginx site using the legacy filename `runegate.conf`, migrate to the new `runegate-nginx.conf`:

1. Remove the old site symlink and file (if present):

   ```bash
   sudo rm -f /etc/nginx/sites-enabled/runegate.conf
   sudo rm -f /etc/nginx/sites-available/runegate.conf
   ```

2. Install the new template and enable it:

   ```bash
   sudo cp /opt/runegate/deploy/nginx/runegate-nginx.conf /etc/nginx/sites-available/
   sudo ln -s /etc/nginx/sites-available/runegate-nginx.conf /etc/nginx/sites-enabled/
   ```

3. Test and reload nginx:

   ```bash
   sudo nginx -t
   sudo systemctl reload nginx
   ```

Notes:
- Keep the HTTP (port 80) server minimal; if using Certbot's nginx authenticator, it will inject the ACME challenge location during renewals.
- Ensure your `RUNEGATE_BASE_URL` is set to your public HTTPS origin (e.g., `https://app.example.com`).

## Optional: Systemd override snippet

The provided unit (`deploy/systemd/runegate.service`) already loads `/etc/runegate/runegate.env` and restarts on failure. If you want to add or tweak settings without editing the installed unit, create a drop‑in override:

```bash
sudo systemctl edit runegate
```

This opens an editor for `/etc/systemd/system/runegate.service.d/override.conf`. Example contents:

```ini
[Service]
# Ensure env file is loaded (kept in sync with your deployment)
EnvironmentFile=/etc/runegate/runegate.env

# Make restarts resilient
Restart=on-failure
RestartSec=5

# Optional: Increase file descriptor limit if your target app streams many files
LimitNOFILE=65536

# Tip: Do not redefine ExecStart here unless you intend to replace it entirely.
```

Apply and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart runegate
sudo systemctl status runegate
```

Logs and verification:

```bash
sudo journalctl -u runegate -f
```

## Post‑Reboot Checks (VPS + Target Host)

After reboots, validate that networking (WireGuard), Runegate, nginx, and your target app are all up and reachable.

1) WireGuard (VPS and target box)

```bash
# Ensure your WireGuard interface (e.g., wg0) is enabled at boot
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
sudo systemctl status wg-quick@wg0

# Verify connectivity from the VPS to the target over VPN
ping -c 3 10.0.0.2
```

2) Target application auto‑start (on target box)

Ensure your protected app (e.g., Gradio/Uvicorn) is managed by systemd and listens on the VPN interface or `0.0.0.0`.

```bash
# Example: enable and check your target app
sudo systemctl enable my-target.service
sudo systemctl start my-target.service
sudo systemctl status my-target.service

# Confirm it’s listening on 0.0.0.0:7860 or 10.0.0.2:7860
ss -ltnp | rg 7860
```

3) Runegate service (VPS)

```bash
sudo systemctl enable runegate
sudo systemctl restart runegate
sudo systemctl status runegate

# Health check via loopback (bypasses nginx)
curl -i http://127.0.0.1:7870/health
```

4) nginx (VPS)

```bash
sudo nginx -t
sudo systemctl reload nginx
sudo systemctl status nginx

# Verify HTTPS → Runegate flow
curl -I https://your-domain.example.com/health
```

5) Target reachability from VPS

```bash
# Verify the VPS can reach the target over WireGuard
curl -i http://10.0.0.2:7860
```

6) Certificates (optional, VPS)

```bash
# If using Certbot, dry-run renewals
sudo certbot renew --dry-run
```

If any of these checks fail, inspect logs:
- Runegate: `sudo journalctl -u runegate -f`
- nginx: `sudo tail -n 100 /var/log/nginx/error.log`
- Target app: `sudo journalctl -u my-target.service -f`
- WireGuard: `sudo journalctl -u wg-quick@wg0 -e`

## Reverse Proxy: Starlette/Uvicorn (FastAPI/Gradio)

When running FastAPI/Starlette/Gradio behind Runegate + nginx, ensure the app trusts proxy headers so it generates the correct scheme and absolute URLs (https + public host) and long‑poll endpoints (e.g., heartbeat, upload progress) work reliably.

### Recommended Uvicorn flags

Start your app with proxy header support and bind to VPN/0.0.0.0:

```bash
uvicorn app:app \
  --host 0.0.0.0 --port 7860 \
  --proxy-headers --forwarded-allow-ips='*'
```

- `--proxy-headers`: Trust `X-Forwarded-*` headers for URL generation.
- `--forwarded-allow-ips='*'`: Accept `X-Forwarded-*` from the proxy. For tighter control, set this to the VPS IP.

### Using ProxyHeadersMiddleware (code)

Alternatively (or additionally), ensure Starlette honors proxy headers in code:

```python
from fastapi import FastAPI
from starlette.middleware.proxy_headers import ProxyHeadersMiddleware

app = FastAPI()
app.add_middleware(ProxyHeadersMiddleware)

@app.get("/health")
def health():
    return {"ok": True}
```

### Gradio notes

- Launch with: `demo.launch(server_name="0.0.0.0", server_port=7860)` so it listens on the VPN/host interface.
- Prefer a dedicated subdomain (no path prefix) so no special `root_path` handling is needed.
- When proxy headers are honored, Gradio should produce absolute links using the public origin (through Runegate), which fixes preview URLs and avoids direct `10.0.0.2:7860` references in the browser.

### Nginx + Runegate recap for proxies

- nginx on the VPS terminates TLS and sets `X-Forwarded-Proto https`.
- Runegate forwards `Host` and passes through `X-Forwarded-Proto` to the upstream.
- Ensure long timeouts and streaming are enabled in nginx and Runegate for large uploads and long‑polling.

## Large Uploads & Downloads (Streaming)

For large files (hundreds of MBs to many GBs) and long‑lived endpoints (heartbeat, upload progress):

- In Runegate env (`/etc/runegate/runegate.env`):

  ```env
  RUNEGATE_STREAM_RESPONSES=true
  ```

- In nginx TLS server for your domain:

  ```nginx
  location / {
      proxy_pass http://127.0.0.1:7870;
      # Streaming & timeouts
      client_max_body_size 10G;
      proxy_request_buffering off;  # stream uploads to Runegate
      proxy_buffering off;          # avoid buffering responses
      proxy_read_timeout 600s;
      proxy_send_timeout 600s;
  }
  ```

- Ensure the target app trusts proxy headers (see Uvicorn flags above) so absolute URLs and schemes are correct.

These settings reduce memory usage, avoid buffering delays, and keep progress/heartbeat endpoints responsive.

## Example systemd unit: Uvicorn/Gradio target app

This example unit manages a FastAPI/Gradio app served by Uvicorn on the target host (aibox). Adjust paths, user, and module accordingly.

File: `deploy/systemd/target-app-uvicorn.service.example`

```ini
[Unit]
Description=Target App (Uvicorn/Gradio)
After=network-online.target wg-quick@wg0.service
Wants=network-online.target

[Service]
Type=simple
User=aiboxapp
Group=aiboxapp
WorkingDirectory=/opt/aibox-app
Environment="PYTHONUNBUFFERED=1"
# Optional: app-specific env vars
EnvironmentFile=-/etc/aibox-app.env

ExecStart=/opt/aibox-app/venv/bin/uvicorn app:app \
  --host 0.0.0.0 --port 7860 \
  --proxy-headers --forwarded-allow-ips='*'

Restart=on-failure
RestartSec=5
LimitNOFILE=65536
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=/opt/aibox-app /var/log/aibox-app /tmp

StandardOutput=journal
StandardError=journal
SyslogIdentifier=aibox-app

[Install]
WantedBy=multi-user.target
```

Install and enable:

```bash
sudo cp deploy/systemd/target-app-uvicorn.service.example /etc/systemd/system/target-app.service
sudo systemctl daemon-reload
sudo systemctl enable --now target-app
sudo systemctl status target-app
```

Notes:
- Ensure your app binds to `0.0.0.0:7860` (or the WireGuard IP) and the firewall allows access from the VPS IP.
- For Gradio, call `demo.launch(server_name="0.0.0.0", server_port=7860)` inside your app.
