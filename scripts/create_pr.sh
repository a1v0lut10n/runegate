#!/bin/bash
# Script to create a GitHub PR with commit messages

# Print banner
echo "⭐ Runegate PR Creator ⭐"
echo "========================"

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

# If no title provided, use the first commit message as title
if [ -z "$PR_TITLE" ]; then
    PR_TITLE=$(git log -1 --pretty=%s)
fi

echo "📊 PR Information:"
echo "  Current branch: $CURRENT_BRANCH"
echo "  Base branch: $BASE_BRANCH"
echo "  Title: $PR_TITLE"

# Generate PR body from commit messages
echo "📝 Generating PR description from commit messages..."
PR_BODY="## Changes in this PR\n\n"

# Add feature description from branch name (convert - to spaces and capitalize)
FEATURE_NAME=$(echo $CURRENT_BRANCH | sed 's/feature\///' | sed 's/-/ /g' | awk '{for(i=1;i<=NF;i++)sub(/./,toupper(substr($i,1,1)),$i)}1')
PR_BODY+="This PR implements the **$FEATURE_NAME** feature.\n\n"

PR_BODY+="## Commit History\n\n"

# Get all commits between base branch and current branch with proper formatting
PR_BODY+="$(git log $BASE_BRANCH..$CURRENT_BRANCH --reverse --pretty=format:"- **%s**\n" | sed 's/^/  /')\n\n"

# For each commit, add its body with proper formatting if it has a body
for COMMIT_HASH in $(git log $BASE_BRANCH..$CURRENT_BRANCH --reverse --format="%H"); do
    # Get commit body (skipping the subject line)
    COMMIT_BODY=$(git log -1 --format="%b" $COMMIT_HASH | grep -v "^$")
    
    # If commit has a body, format it as a nested list with proper indentation
    if [ ! -z "$COMMIT_BODY" ]; then
        # Format each line of the body as a nested bullet point
        FORMATTED_BODY=$(echo "$COMMIT_BODY" | sed 's/^- /  - /' | sed 's/^/  /')
        PR_BODY+="$FORMATTED_BODY\n\n"
    fi
done

# Add checklist
PR_BODY+="## Checklist\n\n"
PR_BODY+="- [ ] Documentation updated\n"
PR_BODY+="- [ ] Tests added/updated\n"
PR_BODY+="- [ ] Code reviewed\n\n"

# Create temp file for PR body
TEMP_FILE=$(mktemp)
echo -e $PR_BODY > $TEMP_FILE

# Show preview
echo "=================="
echo "📄 PR Description:"
echo "=================="
cat $TEMP_FILE
echo "=================="

# Confirm with user
read -p "🔍 Proceed with creating the PR? (y/n): " CONFIRM
if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
    echo "❌ PR creation aborted"
    rm $TEMP_FILE
    exit 1
fi

# Create the PR
echo "🚀 Creating PR..."
gh pr create --base $BASE_BRANCH --title "$PR_TITLE" --body-file $TEMP_FILE

# Clean up
rm $TEMP_FILE

echo "✅ PR creation completed!"
