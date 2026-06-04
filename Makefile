SHELL := /bin/bash

.PHONY: proto build build-go test test-go lint vet fmt ci clean

proto:
	@true

build: proto build-go

build-go:
	go build ./...

test: proto test-go

test-go:
	go test ./...

lint: proto vet

vet:
	go vet ./...

ci: proto vet test-go build-go

fmt:
	gofmt -w $$(find . -type f -name '*.go')

clean:
	@true
