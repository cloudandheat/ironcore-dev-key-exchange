FROM rust:latest AS builder
RUN apt-get update && apt-get install -y protobuf-compiler

WORKDIR /usr/src/app
COPY rust_backend/ ./rust_backend/
COPY proto/ ./proto/

WORKDIR /usr/src/app/rust_backend
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /usr/src/app/rust_backend/target/release/rust_mls_backend /usr/local/bin/
EXPOSE 50051
CMD ["rust_mls_backend"]
