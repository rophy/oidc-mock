IMAGE := oidc-mock

.DEFAULT_GOAL := help

.PHONY: build unit-test e2e-test test lint clean help

build: ## Build Docker image
	docker build -t $(IMAGE) .

unit-test: ## Run unit tests with coverage
	go test -v -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1
	@rm -f coverage.out

e2e-test: ## Run Playwright e2e tests via Docker with coverage
	@mkdir -p /tmp/oidc-mock-e2e-coverdir
	@rm -f /tmp/oidc-mock-e2e-coverdir/*
	GOCOVERDIR=/tmp/oidc-mock-e2e-coverdir go test -tags e2e -v -timeout 120s ./e2e/
	@if ls /tmp/oidc-mock-e2e-coverdir/*.* >/dev/null 2>&1; then \
		echo "--- e2e coverage ---"; \
		go tool covdata percent -i=/tmp/oidc-mock-e2e-coverdir; \
	fi

test: unit-test e2e-test ## Run all tests

lint: ## Run go vet
	go vet ./...

clean: ## Remove build artifacts
	docker rmi $(IMAGE) 2>/dev/null || true

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
