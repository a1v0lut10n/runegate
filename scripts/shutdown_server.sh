#!/bin/bash
# Script to gracefully shut down a running Runegate server

# Print script banner
echo "Runegate Server Shutdown Script"
echo "==============================="

# Find Runegate process - look specifically for the server binary or cargo run
# We use more precise patterns to avoid matching editors or other tools
RUNEGATE_PROCESS=$(pgrep -f "cargo run --bin runegate|cargo run -p runegate|target/debug/runegate|target/release/runegate")

# Check for PID file from our start script
if [ -z "$RUNEGATE_PROCESS" ] && [ -f ".test_server_pid" ]; then
    SAVED_PID=$(cat .test_server_pid)
    if ps -p "$SAVED_PID" > /dev/null; then
        RUNEGATE_PROCESS=$SAVED_PID
    fi
fi

# Check if we found a process
if [ -z "$RUNEGATE_PROCESS" ]; then
    echo "❌ No running Runegate server found."
    exit 1
fi

echo "🔍 Found Runegate server process: $RUNEGATE_PROCESS"

# Send a SIGTERM first for graceful shutdown
echo "🛑 Sending graceful shutdown signal (SIGTERM)..."
kill -15 $RUNEGATE_PROCESS

# Wait a bit to see if it shuts down cleanly
echo "⏳ Waiting for server to shut down..."
for i in {1..5}; do
    sleep 1
    if ! ps -p $RUNEGATE_PROCESS > /dev/null; then
        echo "✅ Runegate server shut down successfully."
        exit 0
    fi
    echo "  Still waiting... ($i/5)"
done

# If it's still running, use SIGKILL as a last resort
if ps -p $RUNEGATE_PROCESS > /dev/null; then
    echo "⚠️ Server didn't shut down gracefully, forcing termination..."
    kill -9 $RUNEGATE_PROCESS
    
    # Check if killed successfully
    sleep 1
    if ! ps -p $RUNEGATE_PROCESS > /dev/null; then
        echo "✅ Runegate server was forcibly terminated."
        exit 0
    else
        echo "❌ Failed to shut down the server. Please check process ID: $RUNEGATE_PROCESS"
        exit 1
    fi
fi
