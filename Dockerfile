# Stage 1: Build Rust backend
FROM rust:latest AS rust-builder
RUN apt-get update && apt-get install -y protobuf-compiler
WORKDIR /usr/src/app
COPY rust_backend/ ./rust_backend/
COPY proto/ ./proto/
WORKDIR /usr/src/app/rust_backend
RUN cargo build --release

# Stage 2: Build Go Agent
FROM golang:latest AS go-builder
RUN apt-get update && apt-get install -y protobuf-compiler
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
ENV PATH="$PATH:$(go env GOPATH)/bin"
WORKDIR /build
COPY proto/ ./proto/
COPY go_app/ ./go_app/
WORKDIR /build/go_app
RUN protoc --go_out=. --go-grpc_out=. --proto_path=../proto ../proto/mls.proto ../proto/agent.proto
RUN go mod tidy
RUN go build -o /bin/agent_app cmd/agent/main.go

# Stage 3: Final Image
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=rust-builder /usr/src/app/rust_backend/target/release/rust_mls_backend /usr/local/bin/
COPY --from=go-builder /bin/agent_app /usr/local/bin/

# Start both the Rust gRPC server and the Go Agent gRPC server
RUN echo '#!/bin/bash\n\
rust_mls_backend &\n\
sleep 2\n\
exec agent_app\n\
' > /start.sh && chmod +x /start.sh

EXPOSE 50051 50052
CMD ["/start.sh"]
