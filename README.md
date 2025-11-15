# CrazyTrip User Session Server

A secure, production-ready backend server for user session management built with Rust and Actix Web.

## Features

- 🔐 **JWT Authentication** with access and refresh tokens
- 🛡️ **Security Middleware** (CORS, rate limiting, security headers)
- 🗄️ **PostgreSQL Database** with connection pooling
- 🔒 **Password Security** with bcrypt hashing
- 📊 **Session Management** with automatic cleanup
- ✅ **Input Validation** and sanitization
- 📝 **Structured Logging** with configurable levels
- 🚀 **Production Ready** with proper error handling

## Architecture

```
src/
├── main.rs          # Server entry point and configuration
├── config.rs        # Environment-based configuration
├── models.rs        # Data models and validation
├── auth.rs          # JWT authentication service
├── database.rs      # PostgreSQL database service
├── middleware.rs    # Security and utility middleware
├── services.rs      # Business logic layer
├── handlers.rs      # HTTP request handlers
└── utils.rs         # Helper functions and utilities
```

## Quick Start

### Prerequisites

- Rust 1.70+ ([Install Rust](https://rustup.rs/))
- PostgreSQL 13+ ([Install PostgreSQL](https://www.postgresql.org/download/))
- Git

### 1. Clone and Setup

```bash
# Clone the repository
cd /Users/geinervillalobos/Documents/dev/crazytrip/server/users

# Copy environment configuration
cp .env.example .env

# Edit .env with your configuration
nano .env
```

### 2. Database Setup

```bash
# Create database
createdb crazytrip_users

# Create user (optional, adjust as needed)
createuser crazytrip_user
psql -c "ALTER USER crazytrip_user PASSWORD 'your_secure_password_here';"
psql -c "GRANT ALL PRIVILEGES ON DATABASE crazytrip_users TO crazytrip_user;"
```

### 3. Install Dependencies

```bash
cargo build
```

### 4. Run the Server

```bash
cargo run
```

The server will start on `http://127.0.0.1:8080` with the following endpoints:

- Health check: `GET /health`
- API status: `GET /api/v1/status`

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/status` | Server status |
| POST | `/api/v1/auth/register` | User registration |
| POST | `/api/v1/auth/login` | User login |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/request-reset` | Request password reset |
| POST | `/api/v1/auth/reset-password` | Reset password |
| POST | `/api/v1/auth/verify-email` | Verify email |

### Protected Endpoints (Require Authentication)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/logout` | Logout user |
| GET | `/api/v1/user/profile` | Get user profile |
| PUT | `/api/v1/user/profile` | Update user profile |
| POST | `/api/v1/user/deactivate` | Deactivate account |
| GET | `/api/v1/user/sessions` | Get user sessions |
| POST | `/api/v1/user/sessions/invalidate-other` | Invalidate other sessions |
| GET | `/api/v1/user/sessions/active-count` | Get active session count |
| DELETE | `/api/v1/user/sessions/{session_id}` | Invalidate specific session |

### Admin Endpoints (Require Admin Role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/admin/users` | Get all users |
| POST | `/api/v1/admin/users/{user_id}/deactivate` | Deactivate user |

## Configuration

The server is configured via environment variables. Copy `.env.example` to `.env` and adjust the values:

### Server Configuration
- `SERVER_HOST`: Server bind address (default: 127.0.0.1)
- `SERVER_PORT`: Server port (default: 8080)
- `SERVER_WORKERS`: Number of worker threads (default: 4)
- `SERVER_ENVIRONMENT`: Environment (development/production)

### Database Configuration
- `DATABASE_HOST`: PostgreSQL host
- `DATABASE_PORT`: PostgreSQL port
- `DATABASE_NAME`: Database name
- `DATABASE_USER`: Database user
- `DATABASE_PASSWORD`: Database password
- `DATABASE_MAX_CONNECTIONS`: Connection pool size

### Authentication Configuration
- `AUTH_JWT_SECRET`: JWT signing secret (**REQUIRED**: ≥256 bits / 32 bytes)
  - Generate with: `openssl rand -hex 32` (64 hex chars) OR `openssl rand -base64 32` (44 base64 chars)
  - **Quantum-safe**: 256-bit keys provide 128-bit post-quantum security
  - Must be kept secret and rotated periodically
- `AUTH_ACCESS_TOKEN_EXPIRATION_MINUTES`: Access token lifetime
- `AUTH_REFRESH_TOKEN_EXPIRATION_HOURS`: Refresh token lifetime
- `AUTH_BCRYPT_COST`: Password hashing cost (default: 12)

### Security Configuration
- `SECURITY_CORS_ALLOWED_ORIGINS`: Comma-separated allowed origins
- `SECURITY_RATE_LIMIT_REQUESTS`: Max requests per window
- `SECURITY_RATE_LIMIT_WINDOW`: Rate limit window in seconds
- `SECURITY_MAX_REQUEST_SIZE`: Max request body size in bytes

## Security Features

- **JWT Authentication**: Stateless authentication with access/refresh tokens
  - **Current version**: `jsonwebtoken 10.2.0` with `aws_lc_rs` crypto backend
  - **Algorithm**: HS256 (HMAC-SHA256) - **Quantum-safe** ✅
  - **Post-quantum security**: 128-bit quantum resistance (sufficient for Q-Day)
  - See [UPGRADE_JSONWEBTOKEN_10.md](./UPGRADE_JSONWEBTOKEN_10.md) for migration details
- **Password Security**: bcrypt hashing with configurable cost
- **Rate Limiting**: Configurable request limits per IP
- **CORS Protection**: Configurable allowed origins
- **Security Headers**: XSS protection, content type options, etc.
- **Input Validation**: Comprehensive request validation
- **SQL Injection Protection**: Parameterized queries
- **Session Management**: Automatic cleanup of expired sessions
- **Dependency Scanning**: Regular `cargo audit` checks (0 vulnerabilities)

## 🔒 Security Audit - Identified Vulnerabilities

### Vulnerability Checklist

- **CRITICAL – Sesiones de refresh guardadas con valores vacíos** (`src/services/mod.rs`, `UserService::refresh_token`): al rotar tokens se inserta una sesión con `token_hash`, `refresh_token_hash` e `ip_address` en blanco, lo que rompe la iluminación de sesiones (el registro falla en PostgreSQL por el campo `INET` y, si llegara a persistir, impediría revocar el token recién emitido). Impacto: imposibilidad de cerrar sesión y riesgo de reutilización de tokens comprometidos. _Mitigación_: almacenar los hashes reales y la metadata del request, reusando la lógica de login/registro.
- **ALTO – Refresh tokens reutilizables sin detección** (`src/services/mod.rs`, `UserService::refresh_token`): se invalida el token previo sin comprobar si existía una sesión activa, por lo que el mismo refresh token firmado puede canjearse ilimitadas veces hasta expirar. Impacto: replay attack ante robo del refresh token. _Mitigación_: exigir `is_active = true`, comprobar filas afectadas y revocar el `jti` tras el primer uso.
- **ALTO – Divulgación de errores internos al cliente** (`src/handlers/mod.rs`, varios endpoints como `refresh_token`, `update_user_profile`, `deactivate_user`): se responde con `err.to_string()` devolviendo mensajes de PostgreSQL y trazas internas. Impacto: revela estructura de la base, nombres de columnas y configuraciones. _Mitigación_: mapear excepciones a mensajes genéricos y registrar el detalle solo en logs internos.
- **MEDIO – Autenticación por cookie sin protección CSRF** (`src/auth/mod.rs`, `extract_token_from_request`): el middleware acepta `access_token` desde cookies sin exigir cabeceras `Authorization` ni token anti-CSRF, exponiendo endpoints sensibles a ataques cross-site cuando el frontend usa cookies. Impacto: ejecución de acciones autenticadas desde sitios maliciosos. _Mitigación_: eliminar la ruta por cookie o añadir doble-submit/Origin checks antes de procesar peticiones con credenciales.
- **MEDIO – Almacenamiento de llaves de rate limiting sin límite** (`src/middleware/mod.rs`, `RateLimitMiddleware`): cada combinación de IP/API key/token genera una entrada permanente en memoria (`HashMap`) que nunca se depura; un atacante puede forzar miles de claves únicas y agotar RAM. _Mitigación_: establecer expiración explícita de claves (TTL) o mover el rate limiting a un backend como Redis.


### Security Status
- 🔴 **CRÍTICO**: 2 vulnerabilidades requieren atención inmediata
- 🟡 **ALTO**: 3 vulnerabilidades requieren corrección prioritaria  
- 🟠 **MEDIO**: 4 vulnerabilidades deben ser abordadas
- 🟢 **BAJO**: 2 vulnerabilidades pueden ser corregidas posteriormente

### Security Tools Used
- `cargo-audit`: Análisis de vulnerabilidades en dependencias de Rust
- `cargo-check`: Validación de código compilable
- Análisis manual de código fuente

## Development

### Running Tests

```bash
cargo test
```

### Code Formatting

```bash
cargo fmt
```

### Linting

```bash
cargo clippy
```

### Building for Production

```bash
cargo build --release
```

## Database Schema

The server automatically creates the following tables:

- `users`: User accounts with secure password storage
- `sessions`: User sessions with token hashes
- `user_roles`: User role assignments (future use)

## Monitoring

The server provides:

- Health check endpoint for load balancers
- Structured logging with configurable levels
- Request/response logging middleware
- Database connection pool monitoring

## Deployment

### Docker (Example)

```dockerfile
FROM rust:1.70-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y libpq-dev ca-certificates
COPY --from=builder /app/target/release/users /usr/local/bin/
EXPOSE 8080
CMD ["users"]
```

### Systemd Service (Example)

```ini
[Unit]
Description=CrazyTrip User Session Server
After=network.target postgresql.service

[Service]
Type=simple
User=crazytrip
EnvironmentFile=/etc/crazytrip/users.env
ExecStart=/usr/local/bin/users
Restart=always

[Install]
WantedBy=multi-user.target
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run `cargo fmt` and `cargo clippy`
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Development — DB & Run (local helper commands)

Below are commands used during local development and debugging for creating the database, running a Postgres container, and using the repository helper binaries.

- Create the database locally with `psql` (if you have psql installed):

```bash
# Create DB using postgres user and password 'moti'
PGPASSWORD=moti psql -U postgres -h 127.0.0.1 -p 5432 -c "CREATE DATABASE crazytrip_users;"
```

- Or use Docker to run a local Postgres instance:

```bash
docker run --name ct-dev-postgres -e POSTGRES_PASSWORD=moti -e POSTGRES_USER=postgres -e POSTGRES_DB=crazytrip_users -p 5432:5432 -d postgres:15
```

- Helper binary: ensure DB exists (connects to `postgres` database and creates `crazytrip_users` if missing):

```bash
cargo run --bin create_db
```

- Helper binary: inspect `sessions` table and test DELETE in a transaction (safe check):

```bash
cargo run --bin check_sessions
```

- Run the main server explicitly (repository contains multiple binaries):

```bash
cargo run --bin crazytrip-user-service
```

- If you previously ran `cargo run` and it fails with `could not determine which binary to run`, use the `--bin` flag as shown above.

- Useful debug flags when running the server:

```bash
# enable debug logs and backtrace
RUST_LOG=debug RUST_BACKTRACE=1 cargo run --bin crazytrip-user-service
```

- Notes:
	- The server contains a development convenience call to `init_schema()` on startup which ensures the required tables exist. In production, prefer running migration scripts instead of auto-creating schema at startup.
	- If port 8080 is already in use, find and stop the process with `lsof -iTCP:8080 -sTCP:LISTEN` then `kill <PID>`.

## Security Audit Summary

The two critical issues (SQL Injection and Exposure of Internal Errors) were remediated:

- SQL Injection: All DB queries use parameterized queries and input validation was added for identifier use-cases; helper scripts no longer build raw SQL from untrusted data.
- Exposure of Internal Errors: Internal error details are now persisted to an `error_logs` table and logged to rotating file logs; HTTP responses return generic messages in production.

Recommended follow-ups: add integration tests to validate parameterization and consider periodic dependency scanning with `cargo-audit`.

## Logging — Secure Logging Verification

The server now sanitizes potentially sensitive fields before writing to logs or the `error_logs` table. Common fields masked: `password`, `token`, `access_token`, `refresh_token`, `authorization`, `auth`, and `email`.

To verify:

1. Trigger an internal error that includes a token or password in the payload (use a test endpoint or simulate via a curl to an endpoint that logs details).

2. Inspect logs (file or stdout) — you should see masked values like `abcd***wxyz` or `it***@example.com` instead of full secrets.

Example:

```bash
# Trigger an error with sensitive data (example payload)
curl -X POST http://127.0.0.1:8080/api/v1/debug/log-error \
	-H "Content-Type: application/json" \
	-d '{"message":"test error","token":"very-long-secret-token-12345","email":"private@example.com"}'

# Check recent error_logs in psql (adjust connection params)
psql -c "SELECT created_at, severity, category, message, details FROM error_logs ORDER BY created_at DESC LIMIT 5;"

# Check stdout/file logger (where flexi_logger writes). You should NOT see full token or password values in the log output.
```

If you see unmasked tokens or passwords in logs, please open an issue and include the example payload you used (avoid posting real secrets).

## Timeouts — Verification

The server exposes configurable timeout settings via environment variables. Example values can be set in your `.env` file:

```
# Keep-alive for persistent connections (seconds)
KEEP_ALIVE_SECONDS=75

# Time allowed to receive the full client request payload (seconds)
CLIENT_TIMEOUT_SECONDS=30

# Time to wait for client disconnect during shutdown (seconds)
CLIENT_SHUTDOWN_SECONDS=5

# General request timeout used in some handlers (fallback)
TIMEOUT_SECONDS=30
```

To verify that timeouts are applied, start the server and use a client that delays sending the request body (e.g., `curl --limit-rate` or a custom script). Requests that exceed `CLIENT_TIMEOUT_SECONDS` will be terminated by the server.

Example: simulate a slow upload (adjust host/port):

```bash
# This simulates a slow POST by limiting curl's upload rate. Adjust file and host.
curl -X POST http://127.0.0.1:8080/api/v1/auth/register \
	-H "Content-Type: application/json" \
	--data-binary @large_payload.json --limit-rate 1 --max-time 120
```

If the server cuts the connection before the full payload is received and returns a 408 or similar error, timeouts are active. Logs will also reflect client request timeouts.

## Security Headers — Verification

The server sets additional security headers which are configurable via environment variables. Example `.env` entries:

```
# Content Security Policy (CSP)
CONTENT_SECURITY_POLICY=default-src 'self'; script-src 'self' 'unsafe-inline'

# HSTS settings
HSTS_PRELOAD=true
HSTS_MAX_AGE=31536000
HSTS_INCLUDE_SUBDOMAINS=true

# Referrer policy
REFERRER_POLICY=strict-origin-when-cross-origin

# Permissions policy (optional)
PERMISSIONS_POLICY=geolocation=(), microphone=()
```

To verify headers are present, start the server and use `curl -I` (head request) or `http` to inspect response headers:

```bash
curl -i http://127.0.0.1:8080/api/v1/status | sed -n '1,40p'

# Or use httpie:
http --headers GET http://127.0.0.1:8080/api/v1/status
```

Look for headers:

- `Content-Security-Policy` (if configured)
- `Strict-Transport-Security` (HSTS)
- `Referrer-Policy`
- `Permissions-Policy` (if configured)

If any header is missing, check your `.env` for the corresponding setting and restart the server.

## Email Validation — Verification

Email validation is now done using the `validator` crate which implements robust email format checks.

To verify:

1. Attempt to register with invalid email formats and ensure the API returns a validation error, for example:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/register \
	-H "Content-Type: application/json" \
	-d '{"email":"not-an-email","username":"u1","password":"Password123"}' | jq '.'
```

Expected: API returns an error indicating invalid email format.

2. Register with a valid email to confirm normal operation.

Automated tests can be added to assert allowed/disallowed formats as part of the test suite.

## CORS Configuration — Verification

The server now enforces explicit origin validation when credentials are allowed. Wildcard `*` is only used when credentials are not requested by the browser. To verify:

1. Ensure `CORS_ALLOWED_ORIGINS` in `.env` contains explicit origins (e.g. `http://localhost:3000,http://127.0.0.1:3000`).
2. From a browser or tool that simulates preflight with credentials, perform an OPTIONS preflight with `Origin` header set to an allowed origin and `Access-Control-Request-Method: POST` and `withCredentials` enabled — response should include `Access-Control-Allow-Origin: <origin>` and `Access-Control-Allow-Credentials: true`.
3. If `Origin` is not in the allowed list but `*` exists in `CORS_ALLOWED_ORIGINS`, the response will include `Access-Control-Allow-Origin: *` but will NOT include `Access-Control-Allow-Credentials`.

Example curl preflight simulation (adjust origin):

```bash
curl -i -X OPTIONS http://127.0.0.1:8080/api/v1/status \
	-H "Origin: http://localhost:3000" \
	-H "Access-Control-Request-Method: POST"
```

Look for `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` headers in the response.

## Session Initialization — Verification

Sessions are now created with all required fields populated (hashed tokens, IP address, user-agent, expiry timestamps). To verify locally:

1. Create a new user (unique email) and login to obtain `access_token` and `refresh_token` (see Token Revocation section).
2. Inspect the `sessions` table in Postgres to verify the inserted row has:
	- `token_hash` non-empty
	- `refresh_token_hash` non-empty
	- `ip_address` set to client IP
	- `user_agent` set (if provided)
	- `expires_at` and `refresh_expires_at` correctly set in the future

Example using `psql` (adjust connection params):

```sql
SELECT id, user_id, token_hash IS NOT NULL AS has_token_hash, refresh_token_hash IS NOT NULL AS has_refresh_hash, ip_address, user_agent, expires_at, refresh_expires_at, is_active
FROM sessions
ORDER BY created_at DESC
LIMIT 5;
```

If any field is empty, please rerun the test with a fresh user email to avoid collisions with previously created sessions.

## Token Revocation (JTI) — Verification

The server now persists revoked JWT IDs (JTI) and rejects requests using revoked tokens. Use these steps to verify locally:

```bash
# Start server
cargo run --bin crazytrip-user-service

# Register a new user (use a unique email for each run)
curl -X POST http://127.0.0.1:8080/api/v1/auth/register \
	-H "Content-Type: application/json" \
	-d '{"email":"it-test+123@example.com","username":"it_test_user","password":"Password123"}'

# Login and capture token
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
	-H "Content-Type: application/json" \
	-d '{"email":"it-test+123@example.com","password":"Password123"}' | jq -r '.data.access_token')

# Access protected endpoint (before logout)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/user/profile

# Logout (this revokes the token)
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/auth/logout

# Try the same token again (should be rejected)
curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/user/profile
```

