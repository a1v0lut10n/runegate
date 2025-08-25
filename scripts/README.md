# Runegate Scripts

This directory contains utility scripts to help with development and testing of Runegate.

## Testing Scripts

- **start_test_server.sh** - Starts a Runegate server in test mode
- **shutdown_server.sh** - Gracefully shuts down a running Runegate server
- **run_integration_tests.sh** - Automates running integration tests against a test server
- **test_token.sh** - Generates and/or verifies JWT tokens using the project's .env

## Development Scripts

- **create_pr.sh** - Creates a GitHub Pull Request with rich descriptions from commit messages

## Usage Examples

### Creating a Pull Request

The `create_pr.sh` script automates creating a PR with a description generated from your commit messages:

```bash
# Basic usage (uses main as base branch)
./scripts/create_pr.sh

# Specify base branch
./scripts/create_pr.sh develop

# Specify base branch and custom PR title
./scripts/create_pr.sh main "My custom PR title"
```

The script will:

1. Extract your current branch name
2. Generate a formatted title from your branch name
3. Collect all commit messages between the base branch and your current branch
4. Create a PR description with commit details and a checklist
5. Show you a preview before submitting
6. Create the PR using GitHub CLI

### Generating a test JWT token

The `test_token.sh` script runs the `examples/test_jwt_validation.rs` helper against your current `.env`:

```bash
# Generate a token for a specific email (default action: create)
./scripts/test_token.sh user@example.com

# Explicitly specify action (create|verify)
./scripts/test_token.sh user@example.com create

# Verify an existing token
./scripts/test_token.sh user@example.com verify <TOKEN>
```

Notes:
- The script automatically loads `.env` from the repository root if present.
- Make sure `RUNEGATE_JWT_SECRET` is set in your `.env` to produce reproducible tokens.
- The example will also print a ready-to-click `/auth?token=...` URL for local testing.
