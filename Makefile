.PHONY: help test test-unit test-integration docker-up docker-down docker-logs clean bench

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: test-unit ## Run all tests (unit only by default)
	@echo "✓ All tests passed"

test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	@go test -v -race -count=1 ./...

test-integration: docker-up ## Run integration tests against Docker Samba server
	@echo "Waiting for Samba server to be ready..."
	@sleep 5
	@echo "Running integration tests..."
	@SMB_SERVER=localhost \
	 SMB_SHARE=testshare \
	 SMB_USERNAME=testuser \
	 SMB_PASSWORD=testpass123 \
	 SMB_DOMAIN=TESTGROUP \
	 go test -v -race -count=1 -tags=integration ./...
	@$(MAKE) docker-down

docker-up: ## Start Docker Samba test server
	@echo "Starting Samba test server..."
	@docker-compose up -d
	@echo "Samba server started on localhost:445"

docker-down: ## Stop Docker Samba test server
	@echo "Stopping Samba test server..."
	@docker-compose down

docker-logs: ## Show Docker Samba server logs
	@docker-compose logs -f samba

docker-restart: docker-down docker-up ## Restart Docker Samba server

clean: ## Clean up Docker resources and test cache
	@echo "Cleaning up..."
	@docker-compose down -v
	@go clean -testcache
	@echo "✓ Cleanup complete"

bench: ## Run performance benchmarks
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem -count=3 ./...

coverage: ## Generate test coverage report
	@echo "Generating coverage report..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

lint: ## Run linter
	@echo "Running linter..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; exit 1; }
	@golangci-lint run ./...
	@echo "✓ Lint passed"

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...
	@echo "✓ Code formatted"

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...
	@echo "✓ Vet passed"

all: fmt vet lint test ## Run all checks
	@echo "✓ All checks passed"
