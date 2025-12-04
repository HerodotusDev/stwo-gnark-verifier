.PHONY: all fmt lint audit test help

# Default target
all: fmt lint audit test

# 1. Formatting
# Uses 'gofmt' as specified in your config
fmt:
	@echo ">> Formatting Go code (gofmt)..."
	gofmt -s -w .
	goimports -l -w .

# 2. Linting
# Runs golangci-lint using your specific .golangci.yml config
lint:
	@echo ">> Linting code..."
	golangci-lint run ./...

# 3. Auditing
# Checks for known vulnerabilities (govulncheck)
# Note: 'gosec' is already running as part of the 'lint' target
audit:
	@echo ">> Checking for vulnerabilities..."
	govulncheck ./...

# 4. Testing
# Runs all tests
test:
	@echo ">> Running tests..."
	go test ./...

# Installation helper
install-tools:
	@echo ">> Installing tools..."
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.7.0
	go install golang.org/x/vuln/cmd/govulncheck@latest