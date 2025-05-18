#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Script to generate secure secrets for Runegate
# Generates JWT secret and session key

set -e

# Environment file to update (optional)
ENV_FILE=${1:-""}

# Banner
echo "============================================="
echo "    Runegate Secret Generator"
echo "============================================="

# Generate JWT secret (64 random bytes, base64 encoded)
JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
echo "JWT Secret:"
echo "$JWT_SECRET"
echo ""

# Generate session key (64 random bytes, hex encoded - required for cookie crate)
# Note: Cookie crate requires at least 64 bytes of raw entropy, encoded as 128 hex chars
SESSION_KEY=$(openssl rand -hex 64 | tr -d '\n')
echo "Session Key:"
echo "$SESSION_KEY"
echo ""

# If an environment file is specified, update it
if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
    echo "Updating environment file: $ENV_FILE"
    
    # Check if the file has the variables (commented or not)
    if grep -q "RUNEGATE_JWT_SECRET" "$ENV_FILE"; then
        # Replace existing variable (even if commented out)
        sed -i "s|#\{0,1\}RUNEGATE_JWT_SECRET=.*|RUNEGATE_JWT_SECRET=$JWT_SECRET|" "$ENV_FILE"
    else
        # Add the variable if it doesn't exist
        echo "RUNEGATE_JWT_SECRET=$JWT_SECRET" >> "$ENV_FILE"
    fi
    
    if grep -q "RUNEGATE_SESSION_KEY" "$ENV_FILE"; then
        # Replace existing variable (even if commented out)
        sed -i "s|#\{0,1\}RUNEGATE_SESSION_KEY=.*|RUNEGATE_SESSION_KEY=$SESSION_KEY|" "$ENV_FILE"
    else
        # Add the variable if it doesn't exist
        echo "RUNEGATE_SESSION_KEY=$SESSION_KEY" >> "$ENV_FILE"
    fi
    
    echo "Environment file updated successfully!"
else
    echo "To add these secrets to your environment, add these lines to your .env file:"
    echo "RUNEGATE_JWT_SECRET=$JWT_SECRET"
    echo "RUNEGATE_SESSION_KEY=$SESSION_KEY"
fi

echo "============================================="
echo "           Secrets Generated!"
echo "============================================="
echo ""
echo "⚠️  SECURITY WARNING: Keep these values private and do not share them. ⚠️"
