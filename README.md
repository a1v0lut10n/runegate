<p align="center">
  <img src="static/img/runegate-logo.svg" alt="Runegate Logo" width="300">
</p>

# Runegate

**Runegate** is a lightweight Rust-based identity proxy that enables secure, user-friendly access to internal or private web applications using **magic email links**.

It authenticates users without passwords by sending them time-limited login links, and forwards their requests to an internal service (such as a Gradio app) upon successful validation.

---

## ✨ Features

- 📧 Magic link login via Gmail SMTP (TLS)
- 🔐 JWT-based session validation
- 🔁 Stateless authentication flow
- 🔒 Secure-by-default with token expiry
- ⏱️ Configurable magic link expiry for longer sessions
- ⚡ Built on `actix-web` for high performance
- 📊 Structured logging with `tracing` for observability
- 🛡️ Configurable rate limiting for enhanced security

---

## 🔄 Recent Changes

- Configurable cookie domain via `RUNEGATE_COOKIE_DOMAIN` (defaults to host-only cookies)
- Configurable session cookie name via `RUNEGATE_SESSION_COOKIE_NAME` (default: `runegate_id`)
- Shared in-memory session store across workers to prevent cross-worker session loss
- Correct middleware ordering so sessions are available during auth checks
- Proxy path fix: `/proxy/*` maps to the target root path `/*`
- Do not forward Runegate’s session cookie to the target service
- Added debug endpoints for troubleshooting: `/debug/session`, `/debug/cookies`, `/debug/protected`

Debug endpoints can now be toggled via the `RUNEGATE_DEBUG_ENDPOINTS` environment variable.

- Identity headers injection (opt-in): When enabled, Runegate injects `X-Runegate-Authenticated`, `X-Runegate-User`, `X-Forwarded-User`, and `X-Forwarded-Email` for authenticated requests and strips any client-supplied versions of these headers.

---

## 📦 Directory Structure

```bash
runegate/
├── src/
│   ├── main.rs              # Main application with auth & proxy functionality
│   ├── auth.rs              # JWT token creation and validation
│   ├── email.rs             # Email configuration types
│   ├── proxy.rs             # Reverse proxy implementation
│   ├── logging.rs           # Structured logging and tracing setup
│   ├── middleware.rs        # Auth middleware implementation
│   ├── send_magic_link.rs   # Email sending functionality
│   ├── memory_session_store.rs # In-memory session store shared across workers
│   └── rate_limit.rs        # Rate limiting implementation
├── static/
│   └── login.html          # Login page for magic link requests
├── examples/
│   ├── send_email.rs       # Example for testing email sending
│   ├── test_target_service.rs  # Demo service to proxy to
│   └── test_jwt_validation.rs  # Tool for testing JWT tokens
├── config/
│   └── email.toml          # SMTP configuration
├── docs/
│   └── architecture-overview.md  # System design and deployment architecture
├── .env                    # Optional: secrets and overrides
├── Cargo.toml
└── README.md
```

---

## 📚 Documentation

Additional documentation is available in the `docs/` directory:

- [Architecture Overview](docs/architecture-overview.md) - System design and deployment architecture

---

## 🛠 Architecture

Runegate uses a reverse proxy architecture to secure access to your internal services:

```bash
┌─────────────┐       ┌───────────────┐       ┌─────────────────┐
│             │       │               │       │                 │
│    User     ├──────►│    Runegate   ├──────►│  Target Service │
│             │       │    (7870)     │       │     (7860)      │
└─────────────┘       └───────────────┘       └─────────────────┘
```

- **Runegate Proxy (Port 7870)**: This is the service users directly access. It handles authentication and proxies requests to the target service.

- **Target Service (Port 7860)**: This is your internal application that Runegate protects. Users never access this directly, only through Runegate after authentication.

When a user clicks a magic link, they're directed to Runegate (port 7870), which validates their token, creates an authenticated session, and then proxies their requests to the target service (port 7860).

This separation keeps your internal service secure while Runegate handles all the authentication logic.

Deployment model: Prefer a dedicated subdomain (for example, `app.example.com`) that proxies all paths to Runegate. Path-based deployments (for example, `example.com/app`) are not supported by default and complicate cookie scoping and redirects.

---

## 🧰 nginx Reverse Proxy (Reference)

When exposing Runegate on the internet, put nginx in front to terminate TLS and forward traffic to Runegate on `127.0.0.1:7870`. Key requirements:

- TLS termination: Serve HTTPS on port 443 and use valid certificates (e.g., Let’s Encrypt).
- HTTP→HTTPS: Listen on port 80 and redirect all traffic to HTTPS.
- Proxy headers: Preserve `Host`, `X-Real-IP`, `X-Forwarded-For`, set `X-Forwarded-Proto https`, and forward cookies.
- WebSockets: Enable upgrade headers and `proxy_http_version 1.1`.
- No path rewriting: Proxy the root to Runegate root; do not alter paths.
- Base URL: Set `RUNEGATE_BASE_URL` to the public HTTPS URL (e.g., `https://app.example.com`).
- Cookies: Leave `RUNEGATE_COOKIE_DOMAIN` unset for host-only cookies unless you require cross-subdomain scope.

Reference nginx config:

```nginx
# Port 80: redirect to HTTPS
server {
    listen 80;
    server_name app.example.com;
    return 301 https://$host$request_uri;
}

# Port 443: TLS termination + reverse proxy
server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate     /etc/letsencrypt/live/app.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    location / {
        proxy_pass http://127.0.0.1:7870;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Cookie $http_cookie;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        client_max_body_size 10G;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_request_buffering off;  # stream large uploads to upstream
        proxy_redirect off;
        proxy_buffering off;
    }
}
```

Let’s Encrypt: If you use Certbot with the nginx authenticator, keep the port 80 server minimal. Certbot injects a temporary `/.well-known/acme-challenge/` location during issuance/renewal.

Target service reachability: Ensure Runegate can reach your protected app (e.g., via WireGuard). For Gradio/Uvicorn, bind to `0.0.0.0` or the VPN IP and allow the VPS IP in your firewall.

---

## ⚙️ Configuration

### Email Setup

Copy the example configuration file to set up your email settings:

```bash
# Copy the example config to create your own configuration
cp config/email.toml.example config/email.toml

# Edit the file with your credentials
editor config/email.toml
```

Then update `config/email.toml` with your Gmail SMTP credentials and message template:

```toml
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_user = "your@gmail.com"
smtp_pass = "your_app_password"

from_address = "Runegate <your@gmail.com>"
subject = "Login Link"
body_template = """Click to log in:

{login_url}

This link is valid for 15 minutes."""
```

> 💡 Use [Gmail App Passwords](https://support.google.com/accounts/answer/185833) with 2FA enabled for better security.

---

## 🚀 Usage

### Running the Proxy

1. Configure your SMTP settings in `config/email.toml`
2. Start the application:

   ```bash
   cargo run
   ```

3. The proxy will be available at `http://localhost:7870`

### Authentication Flow

1. Access any protected resource and you'll be redirected to the login page
2. Enter your email to receive a magic link
3. Check your email and click the link (valid for a configurable period, default: 15 minutes)
4. You'll be authenticated and redirected to the protected resource

Magic links expire after a configurable period (set via `RUNEGATE_MAGIC_LINK_EXPIRY` environment variable). For applications requiring longer sessions, such as video editing or transcription tools, you can extend this period to accommodate extended user workflows without interruption.

### Environment Variables

Optional configuration through environment variables or `.env` file:

```bash
# Defines the operational environment (e.g., `development`, `production`).
# If set to `production`, stricter security rules are enforced:
# - RUNEGATE_JWT_SECRET and RUNEGATE_SESSION_KEY must be set.
# - RUNEGATE_SECURE_COOKIE defaults to `true`.
RUNEGATE_ENV=production

# JWT secret for token signing. Minimum 32 bytes recommended.
# Must be set if RUNEGATE_ENV=production (app will panic otherwise).
# If not set in non-production, a temporary secret is generated (unsafe for production).
RUNEGATE_JWT_SECRET=your_very_secure_random_string_for_jwt_at_least_32_bytes

# Session key for cookie encryption. Minimum 64 bytes required.
# Must be set if RUNEGATE_ENV=production (app will panic otherwise).
# If not set in non-production, a temporary key is generated (unsafe for production).
RUNEGATE_SESSION_KEY=your_very_secure_random_string_for_session_cookies_at_least_64_bytes

# Controls the `Secure` attribute of session cookies (`true` or `false`).
# If unset, defaults to `true` if RUNEGATE_ENV=production, otherwise `false`.
# Set to `true` when serving over HTTPS.
RUNEGATE_SECURE_COOKIE=true

# Optional: Cookie `Domain` attribute. If unset, a host-only cookie is used (recommended).
# Set only if you need the cookie to be sent to a specific parent domain.
# Example: app.example.com
RUNEGATE_COOKIE_DOMAIN=

# Optional: Session cookie name. Defaults to `runegate_id`.
# Change if the target app also uses a cookie named `id` or similar to avoid collisions.
RUNEGATE_SESSION_COOKIE_NAME=runegate_id

# Optional: Enable debug endpoints (/debug/session, /debug/cookies, /debug/protected)
# Defaults: disabled in production, enabled in development unless explicitly set.
RUNEGATE_DEBUG_ENDPOINTS=false

# Optional: Inject identity headers to the target service
# When enabled, Runegate injects X-Runegate-Authenticated, X-Runegate-User,
# X-Forwarded-User, and X-Forwarded-Email for authenticated requests.
# It also strips any client-supplied versions of these headers before forwarding.
# Default: true
RUNEGATE_IDENTITY_HEADERS=true

# Target service URL (defaults to http://127.0.0.1:7860)
RUNEGATE_TARGET_SERVICE=http://your-service-url

# Base URL for magic links (defaults to http://localhost:7870)
RUNEGATE_BASE_URL=https://your-public-url

# Magic link expiry time in minutes (defaults to 15)
RUNEGATE_MAGIC_LINK_EXPIRY=60  # Set longer for apps requiring extended sessions

# Rate limiting configuration
RUNEGATE_RATE_LIMIT_ENABLED=true  # Enable/disable all rate limiting (default: true)
RUNEGATE_LOGIN_RATE_LIMIT=5       # Login attempts per minute per IP address (default: 5)
RUNEGATE_EMAIL_COOLDOWN=300       # Seconds between magic link requests per email (default: 300)
RUNEGATE_TOKEN_RATE_LIMIT=10      # Token verification attempts per minute per IP (default: 10)

# Logging level (defaults to runegate=debug,actix_web=info)
RUST_LOG=runegate=debug,actix_web=info,awc=debug
```

### Logging and Observability

Runegate uses the `tracing` ecosystem for structured logging and observability:

```bash
# Run with default console logging (development mode)
cargo run

# Run with detailed debug logging
RUST_LOG=debug cargo run

# Run with very verbose tracing
RUST_LOG=debug,runegate=trace,actix_web=trace cargo run
```

Log levels can be configured for different components:

- `error`: Only critical errors
- `warn`: Warnings and errors
- `info`: General information plus warnings/errors (default)
- `debug`: Detailed debugging information
- `trace`: Very verbose tracing information

Example log output patterns:

```log
# HTTP requests are automatically logged with timing information
[INFO] runegate::middleware: User is authenticated, allowing access to: /dashboard

# Auth events are logged
[INFO] runegate::auth: Magic link generated for user@example.com
```

#### Configuring Logging Format

Runegate supports two logging formats:

1. **Console format** (default): Readable, colorized logs for development
2. **JSON format**: Structured logs for production and log aggregation systems

The logging format can be configured using the `RUNEGATE_LOG_FORMAT` environment variable, which can be set in your `.env` file or directly in the environment. This eliminates the need to recompile when switching formats.

---

## 🛡️ Rate Limiting

Runegate implements a multi-layered rate limiting system to protect against brute force attacks, abuse, and denial of service attempts. Three distinct rate limiting mechanisms work together to secure the authentication process:

### Rate Limiting Mechanisms

1. **Per-IP Login Rate Limiting**: Caps the number of login attempts from a single IP address
   - Prevents brute force attacks on the login endpoint
   - Default: 5 attempts per minute per IP address

2. **Per-Email Cooldown**: Enforces a cooldown period between magic link requests for the same email
   - Prevents abuse and email flooding
   - Default: 300 seconds (5 minutes) between requests

3. **Token Verification Rate Limiting**: Restricts the number of token verification attempts per IP
   - Protects against brute force attempts to guess valid tokens
   - Default: 10 attempts per minute per IP address

### HTTP Response Behavior

When rate limits are exceeded, Runegate responds with:

- **HTTP 429 Too Many Requests** status code
- **X-RateLimit-Exceeded** header identifying the limit type ("IP" or "Email").
- **X-RateLimit-Reset** header indicating seconds until the limit resets. For IP-based limits (login and token verification), this is typically 60 seconds. For email-based cooldowns, it's the remaining cooldown time.
- JSON response with a descriptive message about the rate limiting.

### Configuration

Rate limiting can be configured via environment variables:

```bash
# Enable or disable all rate limiting (true/false)
RUNEGATE_RATE_LIMIT_ENABLED=true

# Number of login attempts allowed per minute per IP address
RUNEGATE_LOGIN_RATE_LIMIT=5

# Cooldown period in seconds between magic link requests per email
RUNEGATE_EMAIL_COOLDOWN=300

# Number of token verification attempts allowed per minute per IP
RUNEGATE_TOKEN_RATE_LIMIT=10
```

### Testing Rate Limiting

Runegate includes both unit tests and integration tests for rate limiting features:

#### Running Unit Tests

```bash
# Test rate limiting components in isolation
cargo test --test rate_limit_tests
```

#### Running Integration Tests

Automated testing scripts make it easy to test rate limiting against a running server:

```bash
# Test all rate limiting features
./scripts/run_integration_tests.sh

# Test only email cooldown feature
./scripts/run_integration_tests.sh test_email_cooldown_rate_limiting

# Test with rate limiting disabled
RUNEGATE_RATE_LIMIT_ENABLED=false ./scripts/run_integration_tests.sh test_rate_limit_disabled
```

#### Manual Testing

You can also manually test rate limiting by making repeated requests to endpoints:

```bash
# Test login rate limiting
for i in {1..10}; do \
  curl -X POST -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}' \
  http://localhost:7870/login; \
  echo ""; \
done

# Test token verification rate limiting
for i in {1..15}; do \
  curl http://localhost:7870/auth?token=invalid_token; \
  echo ""; \
done
```

### Implementation Details

The rate limiting implementation uses:

- **LRU Cache**: Efficiently tracks email request timestamps
- **In-memory Maps**: Tracks IP-based request counts
- **Time-windowed Approach**: Rate limits reset after the configured period
- **No External Dependencies**: Self-contained implementation for simplicity

All rate limiting state is stored in memory and will reset when the service restarts.

**In your `.env` file:**

```env
# Console logging (default)
RUST_LOG=info

# Or JSON logging for production
RUST_LOG=info
RUNEGATE_LOG_FORMAT=json
```

**Via environment variables:**

```bash
# Run with console logging (default)
RUST_LOG=info cargo run
```

### Rate Limiting and Security

Runegate implements three types of rate limiting mechanisms to protect against abuse:

1. **IP-based Login Rate Limiting** - Prevents brute force login attempts by limiting the number of login requests from the same IP address.
   - Default: 5 attempts per minute per IP address
   - HTTP 429 response when limit exceeded
   - `X-RateLimit-Exceeded: IP` and `X-RateLimit-Reset: 60` headers included.

2. **Email-based Cooldown** - Prevents sending multiple magic links to the same email address in quick succession.
   - Default: 300 seconds (5 minutes) cooldown between requests for the same email
   - `X-RateLimit-Exceeded: Email` and `X-RateLimit-Reset: <remaining_seconds>` headers included.
   - Prevents email flooding and resource exhaustion.

3. **Token Verification Rate Limiting** - Limits attempts to verify auth tokens from the same IP address.
   - Default: 10 verification attempts per minute per IP address
   - HTTP 429 response when limit exceeded
   - `X-RateLimit-Exceeded: IP` and `X-RateLimit-Reset: 60` headers included.

**Configuring Rate Limiting:**

Rate limits can be adjusted or disabled through environment variables:

```env
# Enable or disable all rate limiting
RUNEGATE_RATE_LIMIT_ENABLED=true  # Set to false to disable all rate limiting

# Configure limits
RUNEGATE_LOGIN_RATE_LIMIT=5       # Login attempts per minute per IP
RUNEGATE_EMAIL_COOLDOWN=300       # Seconds between magic links for same email
RUNEGATE_TOKEN_RATE_LIMIT=10      # Token verification attempts per minute
```

**Testing Mode:**

For development and testing, you can disable rate limiting entirely:

```env
RUNEGATE_RATE_LIMIT_ENABLED=false
```

### JSON Logging for Production

```bash
RUST_LOG=info RUNEGATE_LOG_FORMAT=json cargo run > runegate.log

# For Docker or other environments
export RUST_LOG=info
export RUNEGATE_LOG_FORMAT=json
cargo run
```

JSON logs can be easily processed by log aggregation tools like Elasticsearch, Grafana Loki, or other similar systems, and contain all the same contextual information as the console logs but in a machine-readable format.

### Testing Tools

Runegate includes several example scripts for testing:

```bash
# Test email sending
cargo run --example send_email -- recipient@example.com

# Generate a JWT token for testing
cargo run --example test_jwt_validation your@email.com

# Run a test target service
cargo run --example test_target_service
```

### Systemd Deployment

Runegate can be deployed as a systemd service on Debian-based systems with our automated installation system:

```bash
# Clone the repository
git clone https://github.com/a1v0lut10n/runegate.git
cd runegate

# Run the installation script (as root)
sudo ./deploy/install.sh

# Configure your environment
sudo nano /etc/runegate/runegate.env
sudo nano /etc/runegate/config/email.toml

# Start and enable the service
sudo systemctl start runegate
sudo systemctl enable runegate
```

The systemd deployment includes:

- Dedicated low-privilege `runegate` user
- Security hardening with `ProtectSystem=strict`
- Automatic restart on failure
- Journald integration for logging
- Standard Linux directory structure

See the [deployment guide](deploy/README.md) for complete documentation.

---

## 🌐 Production Deployment (HTTPS + Subdomain)

Runegate is designed to sit behind a reverse proxy on a dedicated subdomain.

### 1) DNS
- Create an A/AAAA record for your subdomain, for example `app.example.com`, pointing to your VPS.

### 2) Install as a systemd service
- From this repository:

```bash
git clone https://github.com/a1v0lut10n/runegate.git
cd runegate
sudo ./deploy/install.sh
```

- Configure environment and email:

```bash
sudo nano /etc/runegate/runegate.env
sudo nano /etc/runegate/config/email.toml
```

Recommended `/etc/runegate/runegate.env` for HTTPS deployments:

```env
RUNEGATE_ENV=production
RUNEGATE_JWT_SECRET=...   # >= 32 bytes
RUNEGATE_SESSION_KEY=...  # >= 64 bytes

RUNEGATE_SECURE_COOKIE=true
RUNEGATE_BASE_URL=https://app.example.com
RUNEGATE_TARGET_SERVICE=http://127.0.0.1:7860

# Optional
# RUNEGATE_COOKIE_DOMAIN=app.example.com   # or leave unset for host-only
RUNEGATE_SESSION_COOKIE_NAME=runegate_id

RUST_LOG=info
RUNEGATE_LOG_FORMAT=json
```

Start and enable:

```bash
sudo systemctl start runegate
sudo systemctl enable runegate
```

### 3) Nginx (TLS)

Example Nginx config to terminate TLS and proxy to Runegate:

```nginx
server {
  listen 443 ssl http2;
  server_name app.example.com;

  ssl_certificate     /etc/letsencrypt/live/app.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/app.example.com/privkey.pem;

  # Optional: HSTS
  # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

  location / {
    proxy_pass http://127.0.0.1:7870;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_http_version 1.1;
    proxy_set_header Connection "";

    proxy_read_timeout 300s;
    proxy_send_timeout 60s;
    client_max_body_size 50m;
  }
}

server {
  listen 80;
  server_name app.example.com;
  return 301 https://$host$request_uri;
}
```

Notes:
- Use a single `location /` that proxies to Runegate (no `location /proxy/`).
- Keep `RUNEGATE_BASE_URL` in sync with the public URL.
- Leave `RUNEGATE_COOKIE_DOMAIN` unset for host-only cookies unless a parent domain is needed.
- Run a single Runegate instance (sessions are in-memory). For HA, consider a shared session store.
- Toggle debug endpoints with `RUNEGATE_DEBUG_ENDPOINTS` (recommended off in production).

### 4) Sanity checks

After deploy, verify:

```bash
curl -I https://app.example.com/health
curl https://app.example.com/rate_limit_info
```

Login flow:
- Click magic link.
- You should be redirected to `/proxy/` and land on the target app.

Troubleshooting endpoints (for temporary use):
- `https://app.example.com/debug/cookies` – shows client cookies as seen by Runegate.
- `https://app.example.com/debug/session` – shows server-side session view.
- `https://app.example.com/debug/protected` – passes through auth middleware; returns 200 only if authenticated.

Security tip: Restrict `location /debug/` in Nginx to trusted IPs, or remove these routes after validation.

---

## 🛡️ Security Best Practices

Deploying any application, including Runegate, requires careful attention to security. Here are some best practices to ensure your Runegate deployment is as secure as possible:

### 1. HTTPS is Essential

- **Always deploy Runegate behind a reverse proxy that handles TLS termination (HTTPS).** Examples include Nginx, Caddy, or cloud provider load balancers.
- This is crucial for protecting the confidentiality of data in transit, including session cookies (especially when `RUNEGATE_SECURE_COOKIE` is set to `true`) and the tokens within magic links.
- Do not expose Runegate directly to the internet over HTTP.

### 2. Robust Secret Management

- **Strong Secrets**: Ensure `RUNEGATE_JWT_SECRET` (min 32 bytes) and `RUNEGATE_SESSION_KEY` (min 64 bytes) are cryptographically strong, unique random strings. Do not use default or easily guessable values.
- **Confidentiality**: These secrets must be kept confidential.
- **Avoid Hardcoding**: Do not hardcode secrets into your deployment scripts or source control.
- **Production Methods**: Use secure methods for providing secrets in production:
  - Environment variables (e.g., passed by your orchestrator or systemd unit).
  - `.env` files, ensuring the file has restrictive permissions (e.g., readable only by the `runegate` user).
  - Dedicated secret management systems like HashiCorp Vault, Docker secrets, Kubernetes secrets, or cloud provider secret managers.

### 3. Use `RUNEGATE_ENV=production`

- **Always set `RUNEGATE_ENV=production` in your production deployments.**
- This enables critical security checks, such as ensuring that `RUNEGATE_JWT_SECRET` and `RUNEGATE_SESSION_KEY` are set, and defaults `RUNEGATE_SECURE_COOKIE` to `true`.
- Without this setting, Runegate may use insecure temporary secrets suitable only for development.

### 4. Principle of Least Privilege

- **Dedicated User**: Run the Runegate process as a dedicated, unprivileged user (e.g., `runegate`). The provided systemd unit example already does this.
- **File Permissions**: Ensure the Runegate user only has write access to directories it explicitly needs (e.g., potentially for log files if not using stdout). Configuration files and the application binary should not be writable by the Runegate process user.
- **Systemd Hardening**: The example `runegate.service` file includes `ProtectSystem=strict`, which is a good starting point for systemd-based deployments. Review and apply other relevant hardening options.

### 5. Firewall Configuration

- **Expose Only Necessary Ports**: Configure your server's firewall (e.g., `ufw`, `firewalld`, or cloud provider firewalls) to only expose the port Runegate is listening on (typically 7870, or the port your HTTPS reverse proxy listens on, e.g., 443) to users or the internet.
- **Internal Services**: The target service proxied by Runegate should typically not be directly accessible from the internet.

### 6. Regular Updates and Audits

- **Update Runegate**: Periodically check the Runegate project repository for updates and apply them to your deployment. Updates may contain security patches and bug fixes.
- **Update Dependencies**: Regularly update dependencies by running `cargo update` and rebuilding Runegate.
- **Audit Dependencies**: Use `cargo audit` to check for known vulnerabilities in dependencies and update them as needed.

### 7. Monitoring and Logging

- **Collect Logs**: Configure your production environment to collect logs from Runegate. The JSON logging format (`RUNEGATE_LOG_FORMAT=json`) is recommended for easier parsing and ingestion into log management systems.
- **Monitor Activity**: Regularly monitor logs for suspicious activity, repeated errors, or unusual traffic patterns. This can help detect potential security incidents or operational issues.

By following these best practices, you can significantly improve the security posture of your Runegate deployment.

---

## 🔒 Roadmap

### ✅ Completed

- [x] Email config loading via TOML  
- [x] Magic link generator  
- [x] Auth endpoint to validate token  
- [x] Reverse proxy handler with session check  
- [x] JWT-based session management  
- [x] Static login page UI  
- [x] Rate limiting and logging  
- [x] Production deployment guides  

---

### 🛠️ In Progress

- [ ] Middleware implementation for route protection  
- [ ] Extended error handling and logging  

---

### 🔜 Planned Features

#### 🧭 Routing & Service Support

- [ ] Path-based or domain-based routing to support multiple internal apps  
- [ ] Route configuration in TOML (e.g., `[[routes]]` blocks for services)

#### 🧑‍💼 User Access & Policy

- [ ] Email allowlist and domain restrictions (e.g., `@yourcompany.com`)  
- [ ] Optional one-time-use vs multi-use tokens with configurable TTLs  
- [ ] Session validation tied to IP/User-Agent (opt-in)  
- [ ] Admin API or CLI to manage sessions, revoke tokens, and view active users  

#### ✉️ Email System Enhancements

- [ ] Customizable email templates (HTML and text support)  
- [ ] Pluggable email backend support (SMTP, SendGrid, Mailgun, SES)  
- [ ] Email send audit log and error reporting  

#### 🔐 Security & Hardening

- [ ] Enhanced per-IP and per-email rate limiting configuration  
- [ ] Session signing key rotation support  
- [ ] Token signature algorithm selection (e.g., HS256 vs EdDSA)  
- [ ] Optional CAPTCHA integration (e.g., hCaptcha/Cloudflare Turnstile)

#### 📦 DevOps & Deployment

- [ ] Docker image and `docker-compose.yml` support  
- [ ] Config via environment variables for Docker/Kubernetes  
- [ ] Helm chart for Kubernetes deployments  
- [ ] Redis/Postgres storage integration for sessions and link state  
- [ ] Live reload on config change (optional)

#### 🧰 Developer & Extensibility Features

- [ ] Hook system for custom auth validation and logging  
- [ ] Logging sink options (stdout, file, syslog, remote endpoint)  
- [ ] Web UI for basic metrics and active session inspection  
- [ ] Architecture diagram and full configuration reference in docs  
- [ ] CLI for managing magic links and session state

---

### 🧪 Long-Term / Exploratory Ideas

- [ ] WebAuthn support as an alternative login method  
- [ ] QR-code-based login links  
- [ ] OAuth2 token relay proxy mode (e.g., act as lightweight IdP)  
- [ ] Self-expiring magic link tokens with usage audit  
- [ ] Hardened builds with static linking and binary signing

---

## 🔗 Related Projects

While no single crate offers the exact functionality of `runegate` — a lightweight Rust-based identity proxy using magic-link authentication over email — several existing projects and libraries provide composable building blocks that inspired or overlap with `runegate`'s functionality.

`runegate` is implemented using a combination of:

- [`lettre`](https://crates.io/crates/lettre) for SMTP email delivery,
- [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) for secure, time-limited tokens,
- [`actix-web`](https://crates.io/crates/actix-web) for handling HTTP routes,
- [`actix-session`](https://crates.io/crates/actix-session) for session management, and
- [`governor`](https://crates.io/crates/governor) for rate limiting.

Below is a list of related crates that provide similar or complementary functionality.

### 🔐 Identity & Authentication

- [`oxide-auth`](https://crates.io/crates/oxide-auth) – A full-featured OAuth2 server library for Rust. Good for token-based auth, but not tailored for email-based flows.
- [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) – Essential for encoding and decoding secure JWTs with embedded claims such as expiry and user identity.
- [`actix-identity`](https://crates.io/crates/actix-identity) – Identity middleware for Actix. Useful for managing login state with cookies.

### ✉️ Email & Magic-Link Infrastructure

- [`lettre`](https://crates.io/crates/lettre) – A modern email library for sending SMTP messages securely over TLS or STARTTLS.
- [`uuid`](https://crates.io/crates/uuid) – For generating cryptographically random identifiers used in login links.
- [`rand`](https://crates.io/crates/rand) – Provides secure token or nonce generation.

### 🕸️ Web Frameworks / Glue

- [`actix-web`](https://crates.io/crates/actix-web) – A powerful and performant web framework used to handle routing and request processing.
- [`warp`](https://crates.io/crates/warp) – An alternative web framework with strong type safety and composability.
- [`axum-login`](https://crates.io/crates/axum-login) – A login/session management layer built for Axum. Useful for session-based identity, though it uses password-based auth by default.

### 🧠 High-Level Identity Platforms

- [`auth0`](https://crates.io/crates/auth0) – Integration support for Auth0, a commercial identity provider with passwordless login flows. Suitable for projects using SaaS identity infrastructure.

These libraries can serve as a foundation for your own magic-link or token-based identity proxy solution if you are not using `runegate`.

---

## 🧪 Requirements

- Rust 1.70+
- Valid Gmail account + App Password
- Open ports `7870` (local) or behind Nginx

---

Runegate is designed for simplicity and security when exposing private tools to trusted users — with no passwords to manage.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

Copyright 2025 Aivolution GmbH
---

## ↪️ Migrating From Path-Based to Subdomain

Earlier versions could appear to work behind a path (e.g., `example.com/app`), but reliable operation requires a dedicated subdomain due to cookie scope, redirects, and proxy prefix handling. The current design targets subdomain deployment by default.

Steps to migrate:
- DNS: create `app.example.com` pointing to your VPS.
- Nginx: create a new vhost for `app.example.com` with a single `location /` proxying to Runegate.
- Runegate config:
  - Set `RUNEGATE_BASE_URL=https://app.example.com`.
  - Leave `RUNEGATE_COOKIE_DOMAIN` unset (host-only) unless you need a parent domain.
  - Keep `RUNEGATE_TARGET_SERVICE=http://127.0.0.1:7860`.
- Remove any path-based rewrites (e.g., `location /app/`) that previously attempted to “mount” Runegate under a path.

Note on path-based setups:
- Path-based routing (`example.com/app`) is not supported out-of-the-box. Supporting it would require a configurable base path for all routes, cookie path scoping, and adjusted proxy stripping logic. If you require this, open an issue — it can be added behind a feature flag, but subdomain routing is recommended for simplicity and reliability.

---

## 🪪 Identity To Target

When Runegate authenticates a user, you may want the downstream target service to know who the user is (e.g., to restore per-user state). There are two approaches:

- Headers mode (implemented): inject identity headers into proxied requests
- JWT mode (future): inject a short‑lived signed token the target can verify

### Headers Mode (Implemented)

- Enable with `RUNEGATE_IDENTITY_HEADERS=true` (default true).
- For authenticated requests, Runegate injects these headers and strips any client‑supplied versions:
  - `X-Runegate-Authenticated: true|false`
  - `X-Runegate-User: <email>`
  - `X-Forwarded-User: <email>`
  - `X-Forwarded-Email: <email>`
- Target guidance: read `X-Forwarded-User` or `X-Forwarded-Email` to associate a request with a user.
- Security notes:
  - Keep the target internal (e.g., `127.0.0.1:7860`) so only Runegate can reach it.
  - Do not trust identity headers from the public internet; Runegate strips/re‑injects them.

### JWT Mode (Future Enhancement)

For stronger trust across multiple services, Runegate can inject a short‑lived JWT, signed with a dedicated keypair.

- Request header: `Authorization: Bearer <jwt>` (or a custom header like `X-Runegate-JWT`).
- Claims (example):

```json
{
  "sub": "user@example.com",
  "email": "user@example.com",
  "iat": 1710000000,
  "exp": 1710000600,
  "iss": "runegate",
  "aud": "your-target",
  "sid": "optional-session-id"
}
```

- Recommended algorithms: `RS256` or `EdDSA` (Ed25519). Targets only need the public key.
- Rotation: include a `kid` header; targets can fetch a JWKS or be provisioned with the new public key.

Planned environment variables (subject to change):

```env
# Select identity mode: headers | jwt | none
RUNEGATE_IDENTITY_MODE=jwt

# JWT algorithm: RS256 | EdDSA | HS256
RUNEGATE_DOWNSTREAM_JWT_ALG=RS256

# TTL (seconds) for downstream JWTs
RUNEGATE_DOWNSTREAM_JWT_TTL=600

# Issuer and audience
RUNEGATE_DOWNSTREAM_JWT_ISS=runegate
RUNEGATE_DOWNSTREAM_JWT_AUD=your-target

# Where to place the token
RUNEGATE_DOWNSTREAM_JWT_HEADER=Authorization
RUNEGATE_DOWNSTREAM_JWT_BEARER=true   # prefix with "Bearer "

# Keying (choose one set based on the algorithm)
# RS256 / EdDSA (preferred): Runegate signs with private key; targets verify with public key
RUNEGATE_DOWNSTREAM_JWT_PRIVATE_KEY_PATH=/etc/runegate/keys/downstream_private.pem
# Optional inline alternative
# RUNEGATE_DOWNSTREAM_JWT_PRIVATE_KEY_BASE64=...

# HS256 (shared secret; simpler but less isolated trust)
# RUNEGATE_DOWNSTREAM_JWT_SECRET=your-very-strong-shared-secret

# Optional JWKS publication (if you want targets to fetch keys)
# RUNEGATE_DOWNSTREAM_JWKS_ENABLED=false
# RUNEGATE_DOWNSTREAM_JWKS_PATH=/jwks.json
```

Target verification sketch:

- Python (PyJWT, RS256): load the public key, call `jwt.decode(token, public_key, algorithms=["RS256"], audience="your-target", issuer="runegate")`.
- Node (jose, Ed25519): `jwtVerify(token, publicKey, { algorithms: ["EdDSA"], audience: "your-target", issuer: "runegate" })`.

Security notes:
- Use a separate downstream keypair/secret; do not reuse your magic‑link JWT secret.
- Keep tokens short‑lived (5–10 minutes) and consider including a `sid` claim for optional state binding.
- Ensure targets are not publicly reachable; all traffic should flow via Runegate.
