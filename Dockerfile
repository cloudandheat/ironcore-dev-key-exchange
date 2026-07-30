FROM golang:1.26-trixie AS base-builder

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN apt-get update && apt-get install -y build-essential

WORKDIR /build

COPY rust_mls_bridge/ ./rust_mls_bridge/
WORKDIR /build/rust_mls_bridge
RUN cargo build --release

WORKDIR /build/app
COPY . .

# Critical: CGO_ENABLED=1 is strictly required for Go plugins
ENV CGO_ENABLED=1
ENV CGO_LDFLAGS="-L/build/rust_mls_bridge/target/release -lrust_mls_bridge -lm -ldl -lpthread"

FROM base-builder AS plugin-builder
WORKDIR /build/app

RUN go build -buildmode=plugin -o /build/server.so plugins/server/server.go
RUN go build -buildmode=plugin -o /build/client.so plugins/client/client.go



# An empty image that only holds the files you want to copy to the host
FROM scratch AS plugin-export
COPY --from=plugin-builder /build/server.so /
COPY --from=plugin-builder /build/client.so /




FROM debian:trixie-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

COPY --from=plugin-builder /build/server.so /plugins/server.so
COPY --from=plugin-builder /build/client.so /plugins/client.so

EXPOSE 8080

CMD ["mls_app"]