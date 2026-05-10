# Testing & Ansible Deployment Strategy

As Runegate has matured from a simple stateless proxy into a robust identity gateway relying on PostgreSQL and Redis, transitioning from bash-based deployment scripts (`deploy/install.sh`) to Ansible is the perfect next step.

This plan proposes an infrastructure-as-code architecture combined with a 3-tier testing strategy (Localhost, Intranet, and Google Cloud VPS).

## User Decisions
Based on your feedback:
1. **Ansible Architecture**: Playbooks will be housed in `./infra/ansible`.
2. **Legacy Scripts**: The existing `./deploy` scripts will be preserved.
3. **Infrastructure Topology**: PostgreSQL will be managed via Google Cloud SQL. Redis will run directly on the VPS alongside the Runegate binary.
4. **E2E Tooling**: We will use a lightweight shell-based approach (`curl`, `jq`) for HTTP API integration tests.

---

## 1. Testing Strategy

### Tier 1: Localhost (Development)
The goal here is fast, deterministic feedback during active development.
- **Unit Tests**: Ensure `src/` modules have `#[cfg(test)]` blocks.
- **Integration Tests (Mocked Infrastructure)**:
  - Utilize `sqlx::test` macros. This automatically spins up isolated test databases for each test function and runs migrations, ensuring our database logic is sound without requiring manual Postgres setup.

### Tier 2: Intranet (Staging / System Integration)
The intranet environment serves as a staging ground where the actual infrastructure wiring (Ansible) is tested.
- **Testing**:
  - Run the lightweight shell-based **API Integration Tests** (`infra/tests/run_e2e_tests.sh`) against the live Intranet IP.
  - This verifies that Nginx successfully routes traffic, Runegate can establish real connections to Postgres/Redis, and internal SMTP routing works.

### Tier 3: Google Cloud VPS (Production)
The production environment requires the highest security and stability.
- **Testing**: **Smoke Tests Only**.
  - Destructive or state-mutating tests are NOT run here to avoid polluting the production database.
  - Tests include: Verifying `/health` endpoints and checking Nginx TLS configurations.

---

## 2. Ansible Infrastructure Migration

We will create an idempotent Ansible structure in `infra/ansible`.

### Proposed Ansible Layout
```bash
infra/ansible/
├── environments/
│   ├── intranet/
│   │   ├── group_vars/all.yml    # Intranet-specific vars
│   │   └── hosts.ini             # Intranet VM IP
│   └── gcp_vps/
│       ├── group_vars/all.yml    # GCP-specific vars (Cloud SQL IP)
│       └── hosts.ini             # GCP Public IP
├── roles/
│   ├── common/                   # UFW, basic security
│   ├── redis/                    # Install Redis locally
│   ├── runegate/                 # Build/pull binary, systemd, .env
│   └── nginx/                    # Reverse proxy, certbot/internal certs
├── vault.yml                     # Encrypted secrets (DB_PASS, REDIS_PASS)
├── deploy_runegate.yml           # Main playbook
```

### Secrets Management
We will use **Ansible Vault** to manage secrets like `DATABASE_URL`, `REDIS_URL`, `RUNEGATE_JWT_SECRET`, and OIDC secrets. The Ansible `runegate` role will dynamically template the `.env` file on the target server.

---

## 3. Execution Plan

1. **Phase 1 (Tests)**: Implement `sqlx::test` infrastructure and expand the Rust integration tests for localhost.
2. **Phase 2 (Ansible)**: Scaffold the Ansible directory (`infra/ansible`), roles (`common`, `redis`, `runegate`, `nginx`), and vault structures.
3. **Phase 3 (CI/CD)**: Write the lightweight shell-based test runner script (`infra/tests/run_e2e_tests.sh`) to execute Intranet Integration Tests and GCP Smoke tests post-deployment.
