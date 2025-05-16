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

---

## 📦 Directory Structure

```bash
runegate/
├── src/
│   ├── main.rs              # Main application with auth & proxy functionality
│   ├── auth.rs             # JWT token creation and validation
│   ├── email.rs            # Email configuration types
│   ├── proxy.rs            # Reverse proxy implementation
│   └── send_magic_link.rs  # Email sending functionality
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
```

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
- [ ] Rate limiting and logging
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
