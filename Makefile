BINARY_NAME=ouroboros
VERSION?=dev
BUILD_DIR=bin
GOFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: build test run clean lint install

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/ouroboros/

test:
	go test -v -race ./...

test-short:
	go test -race -count=1 ./pkg/types/ ./internal/red/ ./internal/red/probers/ -run "^Test[^P]"

test-cover:
	go test -race -coverprofile=coverage.out ./pkg/types/ ./internal/red/ ./internal/red/probers/
	go tool cover -func=coverage.out | tail -1

run: build
	./$(BUILD_DIR)/$(BINARY_NAME) $(ARGS)

clean:
	@rm -rf $(BUILD_DIR)
	go clean

lint:
	golangci-lint run ./...

install:
	go install $(GOFLAGS) ./cmd/ouroboros/

build-linux:
	@echo "Building $(BINARY_NAME) for Linux AMD64 (pure Go, no CGO)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/ouroboros/

build-linux-arm64:
	@echo "Building $(BINARY_NAME) for Linux ARM64 (pure Go, no CGO)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/ouroboros/

build-all: build build-linux build-linux-arm64

docker-build:
	docker build -t ouroboros:$(VERSION) .

docker-run:
	docker run --rm -e ANTHROPIC_API_KEY ouroboros:$(VERSION) $(ARGS)
