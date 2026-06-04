# Egress Gateway Service

Egress Gateway is the data-plane service for the Egress Gateway v1 program. This
initial skeleton provides the runtime configuration, process wiring, container,
CI, and Helm chart structure that later OpenZiti bind, HTTP/HTTPS proxying,
secret cache, tracing, and metering work will build on.

## Build

```sh
go build ./...
```

## Run

```sh
export GRPC_ADDRESS=':50051'
go run ./cmd/egress-gateway
```

## Configuration

| Environment variable | Required | Default | Description |
| --- | --- | --- | --- |
| `GRPC_ADDRESS` | No | `:50051` | gRPC health/control listen address. |
| `EGRESS_ADDRESS` | No | `egress:50051` | Internal Egress gRPC target. |
| `SECRETS_SERVICE_ADDRESS` | No | `secrets:50051` | Secrets gRPC target. |
| `NOTIFICATIONS_ADDRESS` | No | `notifications:50051` | Notifications gRPC target. |
| `METERING_ADDRESS` | No | `metering:50051` | Metering gRPC target. |
| `TRACING_ADDRESS` | No | `tracing:50051` | Tracing gRPC target. |
| `ZITI_IDENTITY_FILE` | No | `/var/lib/ziti/identity.json` | Enrolled OpenZiti identity path. |
| `EGRESS_CA_CERT_FILE` | No | `/var/lib/egress-ca/tls.crt` | Platform Egress CA certificate path. |
| `EGRESS_CA_KEY_FILE` | No | `/var/lib/egress-ca/tls.key` | Platform Egress CA key path. |
| `RULE_CACHE_TTL` | No | `15s` | Rule cache TTL fallback. |
| `SECRET_CACHE_TTL` | No | `15s` | Secret cache TTL fallback. |
