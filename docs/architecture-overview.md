# Runegate Deployment Architecture Overview

This document provides an architectural overview of the Runegate system — a secure, email-authenticated proxy and deployment environment for exposing internal applications to trusted users.

---

## 🧭 High-Level Flow

```ascii
Customer Browser
      │
      ▼
https://app.example.com
      │
   ┌──┴─────────────────────┐
   │   Nginx (VPS)          │
   └────────────┬───────────┘
                ▼
      ┌─────────────────────┐
      │ Runegate (Rust)     │
      │  🔒 Magic link auth │
      └────────┬────────────┘
               ▼
   ┌────────────────────────────┐
   │ Reverse proxy to target UI │
   └─────┬───────────┬──────────┘
         ▼           ▼
     WireGuard     Rathole
        VPN        Tunnel
         │           │
         ▼           ▼
     ┌───────────────────────────┐
     │  Private Machine          │
     │   (aibox)                 │     
     │  Target App (e.g., Gradio)│
     └───────────────────────────┘
```

---

## 📦 VPS — What Runs Here

| Component        | Role |
|------------------|------|
| `nginx`          | Front-facing webserver with TLS termination for `app.example.com` |
| `runegate`       | Rust-based identity/auth proxy serving the subdomain root `/` |
| `wireguard`      | VPN endpoint to internal network (primary path to aibox) |
| `rathole-server` | TCP reverse tunnel for fallback access to Gradio |
| `workspace/`     | Cloned sites + apps (`example.com`, etc.) |

---

## 🛡️ Authentication Flow

1. Customer visits: `https://app.example.com`
2. Nginx routes all requests to `runegate` running on `localhost:7870`
3. Runegate checks for valid session or sends magic link
4. Email sent using Gmail + TLS via `lettre` (config in `email.toml`)
5. Customer clicks link → token is validated
6. Authenticated session is established (JWT or cookie)
7. Proxy begins forwarding to the internal target app

---

## 🖥️ Private Machine (aibox) — What Runs Here

| Component          | Role |
|--------------------|------|
| `gradio` app       | Python-based AI frontend |
| `wireguard client` | Connects to VPS, exposes `127.0.0.1:7860` to `10.0.0.2:7860` |
| `rathole client`   | Optional fallback TCP tunnel to VPS |

---

## 🌐 URL Routing via Nginx (VPS)

```nginx
server {
    listen 443 ssl;
    server_name app.example.com;

    # Forward all requests on the subdomain to Runegate
    location / {
        proxy_pass http://localhost:7870;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 🔁 Deployment Flow

### VPS (Public Server) Setup

1. **Install Runegate**: Use the `deploy/install.sh` script to install Runegate and generate necessary secrets

   ```bash
   sudo ./deploy/install.sh
   ```

2. **Configure Nginx**: Set up a reverse proxy to forward requests from your domain to Runegate

   ```bash
   sudo cp deploy/nginx/runegate.conf /etc/nginx/sites-available/
   sudo ln -s /etc/nginx/sites-available/runegate.conf /etc/nginx/sites-enabled/
   ```

3. **Set Up WireGuard**: Create a secure tunnel between your VPS and the private machine

   ```bash
   sudo apt install wireguard
   # Generate and configure WireGuard keys
   ```

4. **Configure Rathole Server**: As a fallback connection method

   ```bash
   # Install and configure rathole server component
   systemctl enable --now rathole.service
   ```

### Private Machine Setup

1. **Run Gradio App**: Start your AI application on localhost

   ```bash
   # Start your Gradio app on port 7860
   ```

2. **Connect to VPS**: Configure WireGuard client and Rathole client

   ```bash
   # Establish WireGuard tunnel to VPS
   # Set up rathole client as backup
   ```

3. **Verify Connection**: Ensure the proxy can reach the Gradio app

Once deployed, users access the protected app securely via the dedicated subdomain (for example, `https://app.example.com`) with email-based authentication.

---

## 🔐 Security Summary

| Layer         | Protection |
|---------------|------------|
| TLS (Nginx)   | HTTPS for all traffic |
| Runegate      | Magic link (JWT) auth |
| VPN           | WireGuard tunnel to aibox |
| Fallback      | Rathole reverse TCP tunnel |

---

This setup exposes only the authentication and proxy layer to the public, while keeping all sensitive processing on a private, hardened machine.

---

## 📌 Notes on Routing Model

- Recommended: Use a dedicated subdomain (for example, `app.example.com`) that proxies all paths to Runegate. This simplifies cookie scoping, redirects, and proxying.
- Path-based mounting (for example, `example.com/app`) is not supported by default and would require explicit base-path handling behind a feature flag.
- Cookie domain: By default, Runegate issues host-only cookies. You can override with `RUNEGATE_COOKIE_DOMAIN` if you need a broader scope. Ensure `RUNEGATE_BASE_URL` reflects the public subdomain for correct magic links.
