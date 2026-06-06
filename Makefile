SHELL := /bin/bash

BUF_INPUT := third_party/agynio-api
BUF_PATHS := \
	--path third_party/agynio-api/proto/agynio/api/agents/v1 \
	--path third_party/agynio-api/proto/agynio/api/egress/v1 \
	--path third_party/agynio-api/proto/agynio/api/identity/v1 \
	--path third_party/agynio-api/proto/agynio/api/metering/v1 \
	--path third_party/agynio-api/proto/agynio/api/notifications/v1 \
	--path third_party/agynio-api/proto/agynio/api/secrets/v1 \
	--path third_party/agynio-api/proto/agynio/api/tracing/v1 \
	--path third_party/agynio-api/proto/agynio/api/ziti_management/v1
.PHONY: proto build build-go test test-go lint vet fmt ci clean

.gen/go/agynio/api/egress/v1/egress.pb.go: \
	third_party/agynio-api/proto/agynio/api/agents/v1/agents.proto \
	third_party/agynio-api/proto/agynio/api/egress/v1/egress.proto \
	third_party/agynio-api/proto/agynio/api/identity/v1/identity.proto \
	third_party/agynio-api/proto/agynio/api/metering/v1/metering.proto \
	third_party/agynio-api/proto/agynio/api/notifications/v1/notifications.proto \
	third_party/agynio-api/proto/agynio/api/secrets/v1/secrets.proto \
	third_party/agynio-api/proto/agynio/api/tracing/v1/tracing.proto \
	third_party/agynio-api/proto/agynio/api/ziti_management/v1/ziti_management.proto \
	buf.gen.yaml buf.yaml
	$(MAKE) proto

proto:
	buf generate $(BUF_INPUT) $(BUF_PATHS)

build: proto build-go

build-go: .gen/go/agynio/api/egress/v1/egress.pb.go
	go build ./...

test: proto test-go

test-go: .gen/go/agynio/api/egress/v1/egress.pb.go
	go test ./...

lint: proto vet

vet: .gen/go/agynio/api/egress/v1/egress.pb.go
	go vet ./...

ci: proto vet test-go build-go

fmt:
	gofmt -w $$(find . -type f -name '*.go')

clean:
	rm -rf .gen
