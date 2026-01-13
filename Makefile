.PHONY: build run test clean docker-build docker-run version release

APP_NAME=s3-gateway
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)"

DOCKER_IMAGE=$(APP_NAME):$(VERSION)
DOCKER_REGISTRY?=ghcr.io/harrykodden

# Build binary
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(APP_NAME) ./cmd/gateway

# Build for multiple platforms
build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(APP_NAME)-linux-amd64 ./cmd/gateway
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(APP_NAME)-linux-arm64 ./cmd/gateway
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(APP_NAME)-darwin-amd64 ./cmd/gateway
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(APP_NAME)-darwin-arm64 ./cmd/gateway
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(APP_NAME)-windows-amd64.exe ./cmd/gateway

# Show version information
version:
	@echo "Version:    $(VERSION)"
	@echo "Commit:     $(COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"

# Run locally
run:
	go run $(LDFLAGS) ./cmd/gateway -config config.yaml

# Run tests
test:
	go test -v -race ./...

# Run tests with coverage
test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run integration tests in Docker container
test-container:
	docker compose run --rm test-lifecycle

# Clean build artifacts
clean:
	rm -f $(APP_NAME) $(APP_NAME)-*
	rm -f coverage.out coverage.html

# Build Docker image
docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(DOCKER_IMAGE) \
		-t $(DOCKER_REGISTRY)/$(APP_NAME):$(VERSION) \
		-t $(DOCKER_REGISTRY)/$(APP_NAME):latest \
		.

# Push Docker image to registry
docker-push:
	docker push $(DOCKER_REGISTRY)/$(APP_NAME):$(VERSION)
	docker push $(DOCKER_REGISTRY)/$(APP_NAME):latest

# Build and push Docker image
docker-release: docker-build docker-push

# Run with docker-compose
docker-run:
	docker compose up -d

# Stop docker-compose
docker-stop:
	docker compose down

# View docker-compose logs
docker-logs:
	docker compose logs -f

# Rebuild and restart docker-compose
docker-restart:
	docker compose up -d --build

# Lint code
lint:
	golangci-lint run

# Format code
fmt:
	go fmt ./...
	gofmt -s -w .

# Download dependencies
deps:
	go mod download
	go mod tidy

# Verify dependencies
verify:
	go mod verify

# Security scan
security:
	gosec ./...

# Update dependencies
update-deps:
	go get -u ./...
	go mod tidy

# Create a new release tag
release:
	@echo "Current version: $(VERSION)"
	@read -p "Enter new version (e.g., v1.0.0): " NEW_VERSION; \
	if [ -z "$$NEW_VERSION" ]; then \
		echo "Error: Version cannot be empty"; \
		exit 1; \
	fi; \
	if ! echo "$$NEW_VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$$'; then \
		echo "Error: Version must be in format vX.Y.Z or vX.Y.Z-suffix (e.g., v1.0.0, v1.0.0-beta)"; \
		exit 1; \
	fi; \
	if git rev-parse "$$NEW_VERSION" >/dev/null 2>&1; then \
		echo "Error: Tag $$NEW_VERSION already exists"; \
		exit 1; \
	fi; \
	echo "Creating release $$NEW_VERSION..."; \
	git tag -a "$$NEW_VERSION" -m "Release $$NEW_VERSION"; \
	echo "Tag created successfully!"; \
	echo ""; \
	echo "To push the tag and trigger CI/CD release:"; \
	echo "  git push origin $$NEW_VERSION"

.DEFAULT_GOAL := build
