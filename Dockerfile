# Multi-stage Dockerfile for DQIX Multi-Language Architecture
# Supports Python, Go, and Rust implementations

# =================================
# Python Implementation Stage
# =================================
FROM python:3.11-slim as python-builder

WORKDIR /app/python

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libc6-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Python files
COPY pyproject.toml README.md ./
COPY dqix/ ./dqix/
COPY dsl/ ./dsl/

# Install Python dependencies and build wheel
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -e .

# =================================
# Go Implementation Stage
# =================================
FROM golang:1.21-alpine as go-builder

WORKDIR /app/go

# Install dependencies
RUN apk add --no-cache ca-certificates git

# Copy Go module files
COPY dqix-go/go.mod dqix-go/go.sum ./
RUN go mod download

# Copy Go source code
COPY dqix-go/ ./
COPY dsl/ ../dsl/

# Build Go binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o dqix-go \
    ./cmd/dqix

# =================================
# Rust Implementation Stage
# =================================
FROM rust:1.75-slim as rust-builder

WORKDIR /app/rust

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Rust files
COPY dqix-rust/Cargo.toml dqix-rust/Cargo.lock ./
COPY dqix-rust/src/ ./src/
COPY dsl/ ../dsl/

# Build Rust binary
RUN cargo build --release

# =================================
# Final Runtime Stage
# =================================
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python implementation
COPY --from=python-builder /app/python /app/python
COPY --from=python-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python-builder /usr/local/bin/dqix /usr/local/bin/dqix-python

# Copy Go implementation
COPY --from=go-builder /app/go/dqix-go /usr/local/bin/dqix-go

# Copy Rust implementation
COPY --from=rust-builder /app/rust/target/release/dqix /usr/local/bin/dqix-rust

# Copy DSL configurations
COPY dsl/ /app/dsl/

# Copy unified CLI script
COPY dqix-cli/dqix-multi /usr/local/bin/dqix-multi

# Create symlinks for easy access
RUN ln -s /usr/local/bin/dqix-python /usr/local/bin/dqix \
    && chmod +x /usr/local/bin/dqix-multi

# Set environment variables
ENV DQIX_DSL_PATH=/app/dsl
ENV PYTHONPATH=/usr/local/lib/python3.11/site-packages
ENV PATH="/usr/local/bin:${PATH}"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD dqix --help || exit 1

# Default command
CMD ["dqix-multi", "--help"]

# Labels
LABEL maintainer="DQIX Team <team@dqix.org>"
LABEL version="1.2.0"
LABEL description="Domain Quality Index - Multi-Language Architecture"
LABEL org.opencontainers.image.source="https://github.com/dqix-org/dqix"
LABEL org.opencontainers.image.documentation="https://dqix.readthedocs.io"
LABEL org.opencontainers.image.licenses="MIT" 