#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Script to create a GitHub PR with commit messages

set -euo pipefail

# Print banner
echo "⭐ Runegate PR Creator ⭐"
echo "========================="

# Check if gh is installed
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI not found. Please install it first: https://cli.github.com/"
    exit 1
fi

# Get current branch name
CURRENT_BRANCH=$(git branch --show-current)
if [ -z "$CURRENT_BRANCH" ]; then
    echo "❌ Failed to get current branch name"
    exit 1
fi

# Default values
BASE_BRANCH=${1:-"main"}
PR_TITLE=${2:-""}

# Derive a human-readable feature name from the branch
# e.g. feature/VTIME-75-upgrade-tusd → "VTIME 75 Upgrade Tusd"
FEATURE_NAME=$(echo "$CURRENT_BRANCH" \
    | sed 's|^feature/||' \
    | sed 's/-/ /g' \
    | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2))}1')

# If no title provided, use the feature name (not last commit)
if [ -z "$PR_TITLE" ]; then
    PR_TITLE="$FEATURE_NAME"
fi

echo "📊 PR Information:"
echo "  Current branch: $CURRENT_BRANCH"
echo "  Base branch: $BASE_BRANCH"
echo "  Title: $PR_TITLE"

# Build PR body into a temp file directly to avoid quoting issues
TEMP_FILE=$(mktemp)

cat >> "$TEMP_FILE" <<EOF
## Changes in this PR

This PR implements the **${FEATURE_NAME}** feature.

## Commit History

EOF

# Add each commit as a top-level bullet with its body as a proper sub-list
for COMMIT_HASH in $(git log "$BASE_BRANCH".."$CURRENT_BRANCH" --reverse --format="%H"); do
    COMMIT_SUBJECT=$(git log -1 --format="%s" "$COMMIT_HASH")
    COMMIT_BODY=$(git log -1 --format="%b" "$COMMIT_HASH" | sed '/^$/d')

    # Top-level bullet: commit subject
    echo "- **${COMMIT_SUBJECT}**" >> "$TEMP_FILE"

    # Sub-list: commit body lines as nested bullets
    # GitHub markdown needs a blank line before a nested list to render properly
    if [ -n "$COMMIT_BODY" ]; then
        echo "" >> "$TEMP_FILE"
        echo "$COMMIT_BODY" | while IFS= read -r line; do
            # If line already starts with "- ", indent it as a sub-bullet
            if echo "$line" | grep -qE '^\s*-\s'; then
                echo "  $line" >> "$TEMP_FILE"
            else
                echo "  - $line" >> "$TEMP_FILE"
            fi
        done
        echo "" >> "$TEMP_FILE"
    fi
done

cat >> "$TEMP_FILE" <<EOF

## Checklist

- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] Code reviewed
EOF

# Show preview
echo "=================="
echo "📄 PR Description:"
echo "=================="
cat "$TEMP_FILE"
echo "=================="

# Confirm with user
read -p "🔍 Proceed with creating the PR? (y/n): " CONFIRM
if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
    echo "❌ PR creation aborted"
    rm "$TEMP_FILE"
    exit 1
fi

# Create the PR
echo "🚀 Creating PR..."
gh pr create --base "$BASE_BRANCH" --title "$PR_TITLE" --body-file "$TEMP_FILE"

# Clean up
rm "$TEMP_FILE"

echo "✅ PR creation completed!"
