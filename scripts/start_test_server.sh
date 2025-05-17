#!/bin/bash
# Script to start a Runegate server for automated testing

# Print script banner
echo "Runegate Test Server Startup Script"
echo "=================================="

# Default values
PORT=${1:-7870}
LOG_LEVEL=${2:-info}
RATE_LIMIT_ENABLED=${3:-true}

# Check if server is already running - use more precise detection patterns
if pgrep -f "cargo run --bin runegate|cargo run -p runegate|target/debug/runegate|target/release/runegate" > /dev/null; then
    echo "❌ A Runegate server is already running. Please stop it first using ./scripts/shutdown_server.sh"
    exit 1
fi

# Also check for PID file
if [ -f ".test_server_pid" ]; then
    SAVED_PID=$(cat .test_server_pid)
    if ps -p "$SAVED_PID" > /dev/null; then
        echo "❌ A Runegate server is already running (PID: $SAVED_PID). Please stop it first."
        exit 1
    else
        # Clean up stale PID file
        rm .test_server_pid
    fi
fi

echo "🚀 Starting Runegate test server..."
echo "  Port: $PORT"
echo "  Log Level: $LOG_LEVEL"
echo "  Rate Limiting: $RATE_LIMIT_ENABLED"

# Set environment variables for the test server
export RUST_LOG=$LOG_LEVEL
export RUNEGATE_RATE_LIMIT_ENABLED=$RATE_LIMIT_ENABLED
export RUNEGATE_LOGIN_RATE_LIMIT=5
export RUNEGATE_EMAIL_COOLDOWN=2  # 2 seconds for faster testing
export RUNEGATE_TOKEN_RATE_LIMIT=10

# Start the server in the background
cd "$(dirname "$0")/.." # Move to project root
cargo run > test_server.log 2>&1 &

# Store the process ID
PID=$!
echo $PID > .test_server_pid

# Wait for the server to start (looking for the "started" message in logs)
echo "⏳ Waiting for server to start..."
for i in {1..10}; do
    sleep 1
    if grep -q "Starting Runegate auth proxy" test_server.log; then
        echo "✅ Runegate test server started successfully (PID: $PID)"
        echo "  Logs available at: $(pwd)/test_server.log"
        exit 0
    fi
    echo "  Still waiting... ($i/10)"
done

# If we got here, server didn't start properly
echo "❌ Server didn't start within the expected time. Check logs at: $(pwd)/test_server.log"
kill $PID 2>/dev/null
exit 1
