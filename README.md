# KII Server

Overview

This repository contains a simple HMAC-authenticated webhook server and a separate client executable.

**Server:** [main.go](main.go) + [server/server.go](server/server.go)
**Client library:** [client/](client)
**Client executable:** [cmd/client/main.go](cmd/client/main.go)

Prerequisites

- Go 1.18+ installed and on your PATH
- Optional: Docker and Docker Compose if you want to run the app in containers

Environment variables

- **SERVER_PORT:** Optional. Port to run the server on (numeric). Default: `5001`.
- **ADMIN_KEY:** Optional but recommended. Admin API key used for admin endpoints.
- **TIMESTAMP_AGE:** Optional. Duration string (e.g. `5m`, `30s`, `2h`) that defines the maximum allowed age of incoming requests. Default: `5m`.
- **ACCESS_KEY / SECRET_KEY:** For the client executable. Provide the credentials used to sign requests.
- **SERVER_URL:** For the client executable. Base URL of the server (e.g. `http://localhost:5001`).

Security note: Avoid committing `SECRET_KEY` or other secrets to source control. Use a secrets manager for production.

Run the server locally

1. From the repo root, set the port and admin key (optional) and run:

```bash
SERVER_PORT=5001 ADMIN_KEY=my-admin-key go run main.go
```

2. If you do not set `SERVER_PORT`, the server will fall back to port `5001`.

Run the client executable

The client is a separate executable under `cmd/client`. Provide `ACCESS_KEY`, `SECRET_KEY` and `SERVER_URL` to run it.

```bash
ACCESS_KEY=your-access SECRET_KEY=your-secret SERVER_URL=http://localhost:5001 go run ./cmd/client
```

Run the local integration helper

A helper script is available at `scripts/run_local.sh`. It runs all tests first, exports verbose test output to `test_results.txt`, then starts the server, waits for the port to become available, and runs the client if tests pass. Server output is written to `server.log` while the script runs.

```bash
chmod +x scripts/run_local.sh
./scripts/run_local.sh
```

Docker and Docker Compose

The repository includes a `Dockerfile` that now runs tests and `go vet` during the build, and writes `test_results.txt` inside the container workspace.

To build and start the app container:

```bash
docker compose -f docker-compose-dev.yml up --build app
```

To run the test service and export verbose results to `test_results.txt`:

```bash
docker compose -f docker-compose-dev.yml run --rm tests
```

If you want to start both services together:

```bash
docker compose -f docker-compose-dev.yml up --build
```

To stop and remove containers:

```bash
docker compose -f docker-compose-dev.yml down
```

API routes

- `POST /webhook` — private, HMAC-authenticated webhook payload endpoint that updates user balances.
- `GET /users` — admin-only endpoint that returns all users.
- `GET /balance/{user}` — admin-only endpoint that returns an individual user with balances.
- `GET /ledger` — admin-only endpoint that returns the transaction ledger.
- `GET /nonces` — admin-only endpoint that returns recorded nonces.

Request signing

- `X-Access-Key` — access key identifying the sender.
- `X-Timestamp` — UNIX seconds timestamp used for replay protection.
- `X-Nonce` — unique nonce per request.
- `X-Signature` — HMAC-SHA256 signature of `timestamp`, `nonce`, and request body.
- `X-Admin-Key` — required for `/webhook` and admin endpoints.

Telemetry and logging

- All incoming requests are wrapped with structured request telemetry.
- Each request is assigned a `request_id` for correlation across request start/end logs.
- Logs include request method, path, remote address, status, and duration.

Admin requests must include `X-Admin-Key`, `X-Signature`, and `X-Nonce` headers.

Balances are stored as decimal strings to preserve ledger precision.

TIMESTAMP handling

- The server expects incoming requests to include a timestamp header (`X-Timestamp`) that is a UNIX seconds integer.
- The server checks request age against `TIMESTAMP_AGE`.
- Examples:
  - `TIMESTAMP_AGE=5m` — 5 minutes
  - `TIMESTAMP_AGE=30s` — 30 seconds

If `TIMESTAMP_AGE` is missing or invalid, the server uses a default of `5m`.

Testing

- Run `go test ./... -v` for verbose test output locally.
- The project also uses `go vet ./...` during Docker builds for additional static checks.
- The local runner `scripts/run_local.sh` runs `go test ./... -v` first and writes all results to `test_results.txt`, then starts the server and executes the client.
- The Docker Compose `tests` service also runs `go test ./... -v | tee test_results.txt` inside the container.

Troubleshooting

- "import cycle not allowed": ensure packages under `client`, `helpers`, and `server` do not import each other circularly. The `client` package is a library; the CLI is in `cmd/client`.
- If the server reports an invalid timestamp, ensure the client sends `X-Timestamp` with `time.Now().Unix()` and `TIMESTAMP_AGE` is large enough.
- If you get permission or binding errors on start, ensure the chosen `SERVER_PORT` is free and you have permission to bind.

File locations

- Server implementation: [server/server.go](server/server.go)
- Client library: [client/client.go](client/client.go)
- Client executable: [cmd/client/main.go](cmd/client/main.go)
- Local runner script: [scripts/run_local.sh](scripts/run_local.sh)
- Docker Compose config: [docker-compose-dev.yml](docker-compose-dev.yml)

