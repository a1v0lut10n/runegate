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

```
runegate/
├── src/
│   └── main.rs
├── config/
│   └── email.toml           # SMTP configuration
├── .env                     # Optional: secrets and overrides
├── Cargo.toml
└── README.md
```

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

Coming soon:
- Start with `cargo run`
- Send a POST request to `/login` with `{"email": "user@example.com"}`
- Email is sent via `lettre` over TLS
- Access proxy is launched on `localhost:7870`

---

## 🔐 Roadmap

- [x] Email config loading via TOML
- [x] Magic link generator
- [ ] Auth endpoint to validate token
- [ ] Reverse proxy handler with session check
- [ ] Rate limiting and logging
- [ ] Cookie-based session fallback (optional)

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
