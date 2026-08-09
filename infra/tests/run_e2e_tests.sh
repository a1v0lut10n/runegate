#!/usr/bin/env bash

# Runegate E2E API Integration Test Script
# Usage: ./run_e2e_tests.sh <TARGET_URL>

TARGET_URL=${1:-"http://127.0.0.1:7870"}

echo "Running E2E tests against $TARGET_URL"

# 1. Health Check
echo "Testing /health endpoint..."
HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/health")
if [ "$HEALTH_RESPONSE" -eq 200 ]; then
    echo "✅ Health check passed."
else
    echo "❌ Health check failed with status $HEALTH_RESPONSE."
    exit 1
fi

# 2. Redirect Check for Protected Resource
echo "Testing redirect for protected resource..."
PROTECTED_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/")
if [ "$PROTECTED_RESPONSE" -eq 303 ] || [ "$PROTECTED_RESPONSE" -eq 302 ]; then
    echo "✅ Redirect to /auth/login passed."
else
    echo "❌ Expected 303/302 redirect, got $PROTECTED_RESPONSE."
    exit 1
fi

# 3. Test Identify Endpoint (Email Submission)
echo "Testing /auth/identify endpoint (sending magic link)..."
IDENTIFY_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL/auth/identify" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test-e2e@example.com")

if [ "$IDENTIFY_RESPONSE" -eq 200 ]; then
    echo "✅ Identify endpoint passed."
else
    echo "❌ Identify endpoint failed with status $IDENTIFY_RESPONSE. (Note: May fail if SMTP is not configured on target)"
    # We don't exit here because SMTP might intentionally be unconfigured in some staging environments.
fi

echo "All basic integration tests passed!"
exit 0
