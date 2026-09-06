BINARY := oidc-mock

.PHONY: build unit-test e2e-test test lint clean help

build: ## Build the binary
	go build -o $(BINARY) .

unit-test: ## Run unit and integration tests with coverage
	go test -v -cover ./...

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
	rm -f $(BINARY)

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
