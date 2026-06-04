# syntax=docker/dockerfile:1.8
ARG GO_VERSION=1.25

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY . .
ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w" -o /out/egress-gateway ./cmd/egress-gateway

FROM alpine:3.21 AS runtime
WORKDIR /app
RUN addgroup -S app && adduser -S -G app app
COPY --from=build /out/egress-gateway /app/egress-gateway
USER app:app
ENTRYPOINT ["/app/egress-gateway"]
