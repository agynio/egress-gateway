# Egress Gateway Service

Egress Gateway is the data-plane service for the Egress Gateway v1 program. It
contains the runtime components for rule caching and evaluation, HTTP forwarding,
header injection, secret caching, Egress CA leaf certificate generation, identity
resolution, tracing summaries, and metering records. The OpenZiti SDK binding is
wired through runtime seams and remains isolated from the pure request-processing
path.

## Build

`make proto` uses the local Buf plugins configured in `buf.gen.yaml`. Install
the protobuf generators before running `make ci` on a clean machine:

```sh
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.0
```

Ensure `$(go env GOPATH)/bin` is on `PATH`.

```sh
make proto
go build ./...
```

## Run

```sh
export GRPC_ADDRESS=':50051'
export ZITI_SERVICE_NAME='egress-rule-<rule-id>' # optional; auto-discovers #egress-services when empty
go run ./cmd/egress-gateway
```

## Configuration

| Environment variable | Required | Default | Description |
| --- | --- | --- | --- |
| `GRPC_ADDRESS` | No | `:50051` | Admin health listen address. |
| `EGRESS_ADDRESS` | No | `egress:50051` | Internal Egress gRPC target. |
| `SECRETS_SERVICE_ADDRESS` | No | `secrets:50051` | Secrets gRPC target. |
| `NOTIFICATIONS_ADDRESS` | No | `notifications:50051` | Notifications gRPC target. |
| `METERING_ADDRESS` | No | `metering:50051` | Metering gRPC target. |
| `TRACING_ADDRESS` | No | `tracing:50051` | Tracing gRPC target. |
| `AGENTS_SERVICE_ADDRESS` | No | `agents:50051` | Agents gRPC target. |
| `ZITI_MANAGEMENT_ADDRESS` | No | `ziti-management:50051` | Ziti Management gRPC target. |
| `ZITI_IDENTITY_FILE` | No | `/var/lib/ziti/identity.json` | Enrolled OpenZiti identity path. |
| `ZITI_SERVICE_NAME` | No | empty | Explicit OpenZiti egress service name to bind; when empty, the gateway binds the first accessible service with the `egress-services` role attribute. |
| `EGRESS_CA_CERT_PATH` | No | `/var/run/agyn/egress-ca/tls.crt` | Platform Egress CA certificate path. |
| `EGRESS_CA_KEY_PATH` | No | `/var/run/agyn/egress-ca/tls.key` | Platform Egress CA key path. |
| `RULE_CACHE_TTL` | No | `15s` | Rule cache TTL fallback. |
| `SECRET_CACHE_TTL` | No | `60s` | Secret cache TTL fallback. |
| `LEAF_CERT_TTL` | No | `10m` | Generated leaf certificate TTL. |
| `LEAF_CERT_CACHE_SIZE` | No | `4096` | Maximum cached leaf certificate count. |
| `FORWARD_TIMEOUT` | No | `30s` | Upstream request timeout. |

## Helm validation

```sh
helm dependency update charts/egress-gateway
helm lint charts/egress-gateway
helm template egress-gateway charts/egress-gateway
```
