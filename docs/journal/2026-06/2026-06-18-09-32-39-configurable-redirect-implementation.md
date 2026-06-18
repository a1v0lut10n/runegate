# Configurable and Backwards-Compatible Runegate Redirect Path

**Date**: 2026-06-18
**Time**: 09:32:39
**Status**: Completed

## Summary

This entry captures the implementation plan and walkthrough to introduce configurable redirect paths in the Runegate gateway. The goal is to allow configuring post-authentication redirect destinations via an environment variable (`RUNEGATE_DEFAULT_REDIRECT`), while defaulting to `/proxy/` to ensure full backwards compatibility for existing crate users.

---

## 1. Implementation Plan

### Motivation
Runegate is a published crate downloaded 2000+ times. Redirecting successful auth flows directly to `/proxy/app` by default breaks backwards compatibility for standard users of the gateway mode. The redirect path must be configurable, defaulting back to the original `/proxy/` path.

### Proposed Changes

#### Runegate Gateway (`runegate`)
- **Modify `src/routes/auth.rs` and `src/routes/mfa.rs`**: Already modified in earlier steps to retrieve redirect path from `RUNEGATE_DEFAULT_REDIRECT` defaulting to `/proxy/`.
- **Modify `src/routes/oidc.rs`**: Change Google callback redirect to fetch from the environment variable instead of using the hardcoded `/proxy/app`.
- **Modify `.env.example` & `README.md`**: Document `RUNEGATE_DEFAULT_REDIRECT` environment variable.

#### Verbatime Deployment (`verbatime`)
- **Modify `defaults/main.yml`**: Add the default configuration variable `runegate_default_redirect: /proxy/app` to preserve dashboard redirect behavior specifically for Verbatime.
- **Modify `runegate.service.j2`**: Template the environment variable `RUNEGATE_DEFAULT_REDIRECT={{ runegate_default_redirect | default('/proxy/') }}` in the systemd service.

---

## 2. Walkthrough & Execution

### Code Modifications

#### OIDC Redirect Config (`runegate`)
In `src/routes/oidc.rs`:
```rust
    let redirect_path = std::env::var("RUNEGATE_DEFAULT_REDIRECT")
        .unwrap_or_else(|_| "/proxy/".to_string());
    HttpResponse::Found()
        .append_header((header::LOCATION, redirect_path))
        .finish()
```

#### Ansible Template updates (`verbatime`)
In `defaults/main.yml`:
```yaml
runegate_default_redirect: /proxy/app
```
In `runegate.service.j2`:
```ini
Environment=RUNEGATE_DEFAULT_REDIRECT={{ runegate_default_redirect | default('/proxy/') }}
```

---

## 3. Verification

### Compilation Check
Verified that `runegate` builds successfully:
```bash
cargo check --manifest-path Cargo.toml
```

### Git Commits & Push
Pushed code changes to both origin repositories:
- `runegate`: `feature/RUN-4-gateway-functionality`
- `verbatime`: `feature/VTIME-94-account-registration`

### Deploy & Run Check
Ran `bootstrap_intranet_gcs.sh` to redeploy the services to the intranet environment (`aibox`):
```bash
./tools/scripts/bootstrap_intranet_gcs.sh
```
Verified that the Systemd service has the correct environment variable loaded:
```bash
systemctl show runegate --property=Environment
# Confirmed output contains: RUNEGATE_DEFAULT_REDIRECT=/proxy/app
```
Tested Google OAuth / Magic Link login flows, verifying redirection directly to `/proxy/app`.
