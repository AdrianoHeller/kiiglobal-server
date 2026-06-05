# KII Server

Overview

This repository contains a simple HMAC-authenticated webhook server and a separate client executable.

**Server:** [main.go](main.go) + [server/server.go](server/server.go)
**Client library:** [client/](client)
**Client executable:** [cmd/client/main.go](cmd/client/main.go)

Prerequisites

- Go 1.18+ installed and on your PATH
- Optional: Docker if you plan to run via docker-compose

Environment variables

- **SERVER_PORT:** Optional. Port to run the server on (numeric). Default: `5001`.
- **ADMIN_KEY:** Optional but recommended. Admin API key used for admin endpoints.
- **TIMESTAMP_AGE:** Optional. Duration string (e.g. `5m`, `30s`, `2h`) that defines the maximum allowed age of incoming requests. Default: `5m` (5 minutes).
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

TIMESTAMP handling

- The server expects incoming requests to include a timestamp header (`X-Timestamp`) that is a UNIX seconds integer.
- The server checks request age against `TIMESTAMP_AGE`. Provide `TIMESTAMP_AGE` as a Go `time.Duration` string. Examples:
  - `TIMESTAMP_AGE=5m` — 5 minutes
  - `TIMESTAMP_AGE=30s` — 30 seconds

If `TIMESTAMP_AGE` is missing or invalid, the server uses a default of `5m`.

Testing

- Run `go test ./...` to verify packages build (no tests currently included).

Troubleshooting

- "import cycle not allowed": ensure packages under `client`, `helpers`, and `server` do not import each other circularly. The `client` package is a library; the CLI is in `cmd/client`.
- If the server reports an invalid timestamp, ensure the client sends `X-Timestamp` with `time.Now().Unix()` and that `TIMESTAMP_AGE` is large enough.
- If you get permission or binding errors on start, ensure the chosen `SERVER_PORT` is free and you have permission to bind.

Next steps

- Consider moving the server CLI into `cmd/server` for symmetry with `cmd/client`.
- Store secrets in environment securely (or use a secret store) for production.

File locations

- Server implementation: [server/server.go](server/server.go)
- Client library: [client/client.go](client/client.go)
- Client executable: [cmd/client/main.go](cmd/client/main.go)

