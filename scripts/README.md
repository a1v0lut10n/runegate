# Runegate Scripts

This directory contains utility scripts to help with development and testing of Runegate.

## Testing Scripts

- **start_test_server.sh** - Starts a Runegate server in test mode
- **shutdown_server.sh** - Gracefully shuts down a running Runegate server
- **run_integration_tests.sh** - Automates running integration tests against a test server

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
