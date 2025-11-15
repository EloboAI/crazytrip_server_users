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
- `AUTH_JWT_SECRET`: JWT signing secret (min 32 characters)
- `AUTH_ACCESS_TOKEN_EXPIRATION_MINUTES`: Access token lifetime
- `AUTH_REFRESH_TOKEN_EXPIRATION_HOURS`: Refresh token lifetime
- `AUTH_BCRYPT_COST`: Password hashing cost

### Security Configuration
- `SECURITY_CORS_ALLOWED_ORIGINS`: Comma-separated allowed origins
- `SECURITY_RATE_LIMIT_REQUESTS`: Max requests per window
- `SECURITY_RATE_LIMIT_WINDOW`: Rate limit window in seconds
- `SECURITY_MAX_REQUEST_SIZE`: Max request body size in bytes

## Security Features

- **JWT Authentication**: Stateless authentication with access/refresh tokens
- **Password Security**: bcrypt hashing with configurable cost
- **Rate Limiting**: Configurable request limits per IP
- **CORS Protection**: Configurable allowed origins
- **Security Headers**: XSS protection, content type options, etc.
- **Input Validation**: Comprehensive request validation
- **SQL Injection Protection**: Parameterized queries
- **Session Management**: Automatic cleanup of expired sessions

## 🔒 Security Audit - Identified Vulnerabilities

### Vulnerability Checklist

| ✅ | Estado | Nombre | Descripción | Recomendación |
|----|--------|--------|-------------|---------------|
| ✅ | CRÍTICA | Confusión de nombres con crate vulnerable | El proyecto se llamaba `users` igual que un crate público vulnerable. Se cambió el nombre del crate a `crazytrip-user-service` | ✅ RESUELTA |
| ❌ | CRÍTICA | SQL Injection | Uso de concatenación de strings en consultas SQL en lugar de parámetros preparados | Implementar validación de entrada robusta con librerías como `validator` |
| ❌ | CRÍTICA | Exposición de Información Sensible | Manejo de errores que expone detalles internos del sistema | Usar mensajes de error genéricos en producción |
| ❌ | ALTA | Rate Limiting Ineficaz | Rate limiting solo por IP, fácilmente bypassable | Implementar rate limiting por usuario + IP con tokens de API |
| ❌ | ALTA | Falta de Validación JWT | No se valida el campo JTI para prevenir replay attacks | Implementar lista negra de tokens revocados |
| ❌ | ALTA | Sesiones No Seguras | Campos de sesión vacíos o no inicializados correctamente | Inicializar correctamente todos los campos de sesión |
| ❌ | MEDIA | CORS Mal Configurado | Permite credenciales con wildcard origins | Lista explícita de orígenes permitidos |
| ❌ | MEDIA | Validación de Email Débil | Validación básica que permite emails inválidos | Usar regex robusto o librería de validación |
| ❌ | MEDIA | Falta de Logging Seguro | Logging de información potencialmente sensible | Sanitizar datos antes de loggear |
| ❌ | MEDIA | Timeouts No Configurados | Sin timeouts configurados para requests | Configurar timeouts apropiados |
| ❌ | MEDIA | Headers de Seguridad Incompletos | Falta CSP, HSTS preload y otros headers importantes | Agregar headers de seguridad adicionales |
| ❌ | MEDIA | Dependencias Vulnerables | Librerías no mantenidas con bugs de seguridad | Remover dependencias no usadas o actualizar |
| ❌ | BAJA | Secrets en Variables de Entorno | JWT_SECRET puede estar sin protección | Usar secret management seguro (Vault, AWS Secrets Manager) |
| ❌ | BAJA | Configuración por Defecto Insegura | Valores por defecto demasiado permisivos | Valores más restrictivos por defecto |

### Security Status
- 🔴 **CRÍTICO**: 4 vulnerabilidades requieren atención inmediata
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