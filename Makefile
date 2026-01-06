.PHONY: all build clean test install run help benchmark lint

BINARY_NAME=attack
GO=go
GOFLAGS=-ldflags="-s -w"

all: clean build

build:
	@echo "Building..."
	@$(GO) build $(GOFLAGS) -o $(BINARY_NAME) ./cmd/main.go
	@chmod +x launcher.py launcher.sh
	@echo "Build complete: $(BINARY_NAME)"

build-all:
	@echo "Building for all platforms..."
	@GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINARY_NAME)-linux-amd64 ./cmd/main.go
	@GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BINARY_NAME)-linux-arm64 ./cmd/main.go
	@GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINARY_NAME)-darwin-amd64 ./cmd/main.go
	@GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BINARY_NAME)-darwin-arm64 ./cmd/main.go
	@GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BINARY_NAME)-windows-amd64.exe ./cmd/main.go
	@echo "Cross-compilation complete"

clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME) $(BINARY_NAME)-*
	@rm -rf bin/ dist/ build/
	@$(GO) clean
	@echo "Clean complete"

test:
	@echo "Running tests..."
	@$(GO) test -v ./...

test-coverage:
	@echo "Running tests with coverage..."
	@$(GO) test -coverprofile=coverage.out ./...
	@$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

benchmark:
	@echo "Running benchmarks..."
	@$(GO) test -bench=. -benchmem ./...

lint:
	@echo "Running linters..."
	@gofmt -l -w .
	@$(GO) vet ./...

install:
	@echo "Installing dependencies..."
	@$(GO) mod download
	@$(GO) mod tidy
	@echo "Dependencies installed"

run:
	@python3 launcher.py

run-quick:
	@python3 launcher.py --quick

deps-update:
	@echo "Updating dependencies..."
	@$(GO) get -u ./...
	@$(GO) mod tidy

docker-build:
	@docker build -t advanced-attack-tool .

docker-run:
	@docker run -it --rm advanced-attack-tool

help:
	@echo "Available targets:"
	@echo "  make build         - Build binary"
	@echo "  make build-all     - Cross-compile for all platforms"
	@echo "  make clean         - Remove binaries and build artifacts"
	@echo "  make test          - Run tests"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make benchmark     - Run benchmarks"
	@echo "  make lint          - Run linters and formatters"
	@echo "  make install       - Install dependencies"
	@echo "  make run           - Run launcher"
	@echo "  make run-quick     - Run launcher in quick mode"
	@echo "  make deps-update   - Update all dependencies"
	@echo "  make docker-build  - Build Docker image"
	@echo "  make docker-run    - Run Docker container"
