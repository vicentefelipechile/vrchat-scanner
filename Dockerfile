# Stage 1: build the Rust binary
FROM rust:1.88-slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release

# Stage 2: minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/vrcstorage-scanner .

EXPOSE 8080
CMD ["./vrcstorage-scanner", "serve", "--port", "8080"]
