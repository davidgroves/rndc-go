.PHONY: build test test-integration cover lint fmt pre-commit

build:
	go build -o rndc-go ./cmd/rndc-go

test:
	go test -race ./...

test-integration:
	go test -tags integration -race -count=1 ./...

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out | tail -n 1

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

pre-commit:
	pre-commit run --all-files
