#!/usr/bin/env bash
set -euo pipefail

# Local runner: exports env vars, starts the server, waits for it, runs the client,
# then shuts the server down. Make executable: chmod +x scripts/run_local.sh

# Defaults (can override by exporting before running)
: "${SERVER_PORT:=5001}"
: "${ADMIN_KEY:=admin-secret}"
: "${TIMESTAMP_AGE:=5m}"
: "${ACCESS_KEY:=local-access}"
: "${SECRET_KEY:=local-secret}"
: "${SERVER_URL:=http://localhost:${SERVER_PORT}}"

export SERVER_PORT ADMIN_KEY TIMESTAMP_AGE ACCESS_KEY SECRET_KEY SERVER_URL

echo "ENV: SERVER_PORT=$SERVER_PORT ADMIN_KEY=$ADMIN_KEY TIMESTAMP_AGE=$TIMESTAMP_AGE"

# Start server in background and capture PID
echo "Starting server (go run main.go)..."
nohup go run main.go > server.log 2>&1 &
SERVER_PID=$!

echo "Server PID: $SERVER_PID (logs -> server.log)"

# Ensure server is killed on exit
cleanup() {
  echo "Stopping server (PID $SERVER_PID)..."
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for server port to become available
echo "Waiting for server to accept connections on port $SERVER_PORT..."
RETRIES=30
for i in $(seq 1 $RETRIES); do
  if nc -z localhost "$SERVER_PORT" 2>/dev/null; then
    echo "Server is accepting connections"
    break
  fi
  sleep 1
done

if ! nc -z localhost "$SERVER_PORT" 2>/dev/null; then
  echo "Server did not start within expected time. Last 50 lines of server.log:" >&2
  tail -n 50 server.log >&2 || true
  exit 1
fi

# Run client (will use exported ACCESS_KEY/SECRET_KEY/SERVER_URL)
echo "Running client (go run ./cmd/client)..."
go run ./cmd/client
CLIENT_EXIT=$?

echo "Client finished with exit code $CLIENT_EXIT"

# Script will exit and trigger trap to stop server
exit $CLIENT_EXIT
