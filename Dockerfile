# syntax=docker/dockerfile:1

# ----------- Build Stage -----------
FROM rust:1.75-alpine AS builder
LABEL stage=builder
WORKDIR /app

# Instala dependencias necesarias para build
RUN apk add --no-cache musl-dev openssl-dev pkgconfig git

# Copia solo los archivos necesarios para compilar
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations

# Compila en modo release
RUN cargo build --release --bin crazytrip-server-users

# ----------- Runtime Stage -----------
FROM alpine:3.19
LABEL maintainer="EloboAI"
WORKDIR /app

# Crea usuario no-root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copia binario y archivos necesarios
COPY --from=builder /app/target/release/crazytrip-server-users ./crazytrip-server-users
COPY migrations ./migrations

# Variables de entorno (ajusta según tu config)
ENV RUST_LOG=info \
    PORT=8080

# Exponer puerto
EXPOSE 8080

# Healthcheck (ajusta endpoint si tienes /health)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -qO- http://localhost:8080/health || exit 1

# Usa usuario no-root
USER appuser

# CMD recomendado (array)
CMD ["./crazytrip-server-users"]
