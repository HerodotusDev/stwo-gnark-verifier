.PHONY: all fmt lint audit test

# Resolve the Go binary path dynamically
GOBIN := \$(shell go env GOPATH)/bin

# Default target
all: fmt lint audit

# 1. Formatting
# Uses 'gofmt' (standard) and 'goimports' (from GOBIN)
fmt:
	@echo ">> Formatting Go code (gofmt)..."
	gofmt -s -w .
	$(GOBIN)/goimports -l -w .

# 2. Linting
# Runs golangci-lint from GOBIN
lint:
	@echo ">> Linting code..."
	$(GOBIN)/golangci-lint run ./...

# 3. Auditing
# Checks for vulnerabilities using govulncheck from GOBIN
audit:
	@echo ">> Checking for vulnerabilities..."
	$(GOBIN)/govulncheck ./...

# 4. Testing
# Runs all tests (go is usually in system PATH, so we leave it raw)
test:
	@echo ">> Running tests..."
	go test ./...

# Installation helper
install-tools:
	@echo ">> Installing tools..."
	go install golang.org/x/tools/cmd/goimports@v0.39.0
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.7.0
	go install golang.org/x/vuln/cmd/govulncheck@v1.1.4