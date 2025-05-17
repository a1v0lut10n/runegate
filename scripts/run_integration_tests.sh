#!/bin/bash
# Script to start server, run integration tests, and shut down server

# Print script banner
echo "Runegate Integration Test Runner"
echo "==============================="

# Default values
TEST_NAME=${1:-""}
RATE_LIMIT_ENABLED=${2:-true}

# Prepare command
if [ -z "$TEST_NAME" ]; then
    TEST_COMMAND="cargo test --test api_rate_limit_tests -- --ignored"
    echo "🧪 Running all integration tests..."
else
    TEST_COMMAND="cargo test --test api_rate_limit_tests $TEST_NAME -- --ignored"
    echo "🧪 Running specific test: $TEST_NAME"
fi

echo "  Rate limiting enabled: $RATE_LIMIT_ENABLED"

# Step 1: Start the server
echo "🚀 Starting test server..."
./scripts/start_test_server.sh 7870 debug $RATE_LIMIT_ENABLED

# Check if server started successfully
if [ $? -ne 0 ]; then
    echo "❌ Failed to start test server. Aborting tests."
    exit 1
fi

# Step 2: Wait a bit more to ensure server is fully ready
echo "⏳ Waiting for server to be fully ready..."
sleep 2

# Step 3: Run the tests
echo "▶️ Running integration tests..."
$TEST_COMMAND
TEST_EXIT_CODE=$?

# Step 4: Shutdown the server
echo "🛑 Shutting down test server..."
./scripts/shutdown_server.sh

# Report results
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ Integration tests completed successfully!"
else
    echo "❌ Integration tests failed with exit code: $TEST_EXIT_CODE"
fi

exit $TEST_EXIT_CODE
