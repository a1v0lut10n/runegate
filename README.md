# Runegate

**Runegate** is a lightweight Rust-based identity proxy that enables secure, user-friendly access to internal or private web applications using **magic email links**.

It authenticates users without passwords by sending them time-limited login links, and forwards their requests to an internal service (such as a Gradio app) upon successful validation.

---

## ✨ Features

- 📧 Magic link login via Gmail SMTP (TLS)
- 🔐 JWT-based session validation
- 🔁 Stateless authentication flow
- 🔒 Secure-by-default with token expiry
- ⚡ Built on `actix-web` for high performance
- 📊 Structured logging with `tracing` for observability
- 🛡️ Configurable rate limiting for enhanced security

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
│   └── send_magic_link.rs   # Email sending functionality
├── static/
│   └── login.html          # Login page for magic link requests
├── examples/
│   ├── send_email.rs       # Example for testing email sending
│   ├── test_target_service.rs  # Demo service to proxy to
│   └── test_jwt_validation.rs  # Tool for testing JWT tokens
├── config/
│   └── email.toml          # SMTP configuration
├── .env                    # Optional: secrets and overrides
├── Cargo.toml
└── README.md
```

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

---

## ⚙️ Configuration

Set up `config/email.toml` with your Gmail SMTP and message template:

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

> 💡 Use [Gmail App Passwords](https://support.google.com/accounts/answer/185833) with 2FA enabled.

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
3. Check your email and click the link
4. You'll be authenticated and redirected to the protected resource

### Environment Variables

Optional configuration through environment variables or `.env` file:

```bash
# JWT secret for token signing (recommended for production)
RUNEGATE_JWT_SECRET=your_secure_jwt_secret

# Session key for cookies (recommended for production)
RUNEGATE_SESSION_KEY=your_secure_session_key

# Target service URL (defaults to http://127.0.0.1:7860)
RUNEGATE_TARGET_SERVICE=http://your-service-url

# Base URL for magic links (defaults to http://localhost:7870)
RUNEGATE_BASE_URL=https://your-public-url

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
- **X-RateLimit-Exceeded** header identifying the limit type ("IP" or "Email")
- **X-RateLimit-Reset** header indicating seconds until the limit resets
- JSON response with a descriptive message about the rate limiting

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
   - X-RateLimit-* headers included in responses

2. **Email-based Cooldown** - Prevents sending multiple magic links to the same email address in quick succession.
   - Default: 300 seconds (5 minutes) cooldown between requests for the same email
   - Remaining time is returned in error response
   - Prevents email flooding and resource exhaustion

3. **Token Verification Rate Limiting** - Limits attempts to verify auth tokens from the same IP address.
   - Default: 10 verification attempts per minute per IP address
   - Prevents brute-forcing of JWT tokens

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

---

## 🔒 Roadmap

- [x] Email config loading via TOML
- [x] Magic link generator
- [x] Auth endpoint to validate token
- [x] Reverse proxy handler with session check
- [x] JWT-based session management
- [x] Static login page UI
- [x] Rate limiting and logging
- [ ] Middleware implementation for route protection
- [ ] Extended error handling and logging
- [ ] Production deployment guides

---

## 🔗 Related Projects

- `ailanthus-deploy`: Infrastructure orchestration and deploy automation
- `neufallenbach`: Gradio-based AI frontend protected by Runegate

---

## 🧪 Requirements

- Rust 1.70+
- Valid Gmail account + App Password
- Open ports `7870` (local) or behind Nginx

---

Runegate is designed for simplicity and security when exposing private tools to trusted users — with no passwords to manage.
