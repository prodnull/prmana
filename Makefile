# Makefile for unix-oidc
#
# Usage:
#   make build          # Build PAM module in Docker (cross-platform)
#   make build-native   # Build natively (Linux only)
#   make test           # Run unit tests
#   make test-all       # Run all tests (unit + integration)
#   make dev-up         # Start test environment
#   make dev-down       # Stop test environment

.PHONY: build build-native test test-unit test-integration test-all \
        clean dev-up dev-down dev-logs dev-status \
        lint fmt check install help

COMPOSE_FILE := docker-compose.test.yaml

# Default target
.DEFAULT_GOAL := help

#==============================================================================
# Build Targets
#==============================================================================

## Build PAM module in Docker (works on any OS)
build:
	docker build -f Dockerfile.build -t unix-oidc-build .
	@docker rm -f unix-oidc-build-tmp 2>/dev/null || true
	docker create --name unix-oidc-build-tmp unix-oidc-build
	mkdir -p target/release
	docker cp unix-oidc-build-tmp:/build/target/release/libpam_unix_oidc.so target/release/
	docker rm unix-oidc-build-tmp
	@echo "Built: target/release/libpam_unix_oidc.so"

## Build natively (requires Linux with libpam-dev)
build-native:
	cargo build --release

## Build for development (debug mode)
build-dev:
	cargo build

#==============================================================================
# Test Targets
#==============================================================================

## Run unit tests only
test: test-unit

test-unit:
	cargo test --all-features

## Run unit tests with verbose output
test-verbose:
	cargo test --all-features -- --nocapture

## Run integration tests (requires test environment)
test-integration:
	@if ! docker compose -f $(COMPOSE_FILE) ps | grep -q "healthy"; then \
		echo "Starting test environment..."; \
		$(MAKE) dev-up; \
	fi
	./test/scripts/run-integration-tests.sh

## Run specific integration test category
test-connectivity:
	./test/scripts/run-integration-tests.sh connectivity

test-oidc:
	./test/scripts/run-integration-tests.sh oidc

test-sudo:
	./test/scripts/run-integration-tests.sh sudo

## Run all tests (unit + integration)
test-all: test-unit dev-up test-integration dev-down

## Run tests with coverage (requires cargo-tarpaulin)
test-coverage:
	cargo tarpaulin --all-features --out Html

#==============================================================================
# Development Environment
#==============================================================================

## Start test environment (Keycloak, LDAP, test-host)
dev-up:
	docker compose -f $(COMPOSE_FILE) up -d
	./test/scripts/wait-for-healthy.sh

## Stop test environment
dev-down:
	docker compose -f $(COMPOSE_FILE) down

## Stop and remove volumes
dev-clean:
	docker compose -f $(COMPOSE_FILE) down -v

## Show test environment logs
dev-logs:
	docker compose -f $(COMPOSE_FILE) logs -f

## Show logs for specific service
dev-logs-keycloak:
	docker compose -f $(COMPOSE_FILE) logs -f keycloak

dev-logs-ldap:
	docker compose -f $(COMPOSE_FILE) logs -f openldap

dev-logs-host:
	docker compose -f $(COMPOSE_FILE) logs -f test-host

## Show test environment status
dev-status:
	@echo "=== Docker Compose Status ==="
	docker compose -f $(COMPOSE_FILE) ps
	@echo ""
	@echo "=== Service Health ==="
	@docker compose -f $(COMPOSE_FILE) ps --format json 2>/dev/null | jq -r '.[] | "\(.Name): \(.Health)"' 2>/dev/null || \
		docker compose -f $(COMPOSE_FILE) ps

## Restart test environment
dev-restart: dev-down dev-up

## Get a test token from Keycloak
dev-token:
	@./test/scripts/get-test-token.sh

#==============================================================================
# Code Quality
#==============================================================================

## Run all code quality checks
check: fmt-check lint

## Check formatting
fmt-check:
	cargo fmt --all -- --check

## Apply formatting
fmt:
	cargo fmt --all

## Run clippy linter
lint:
	cargo clippy --all-targets --all-features -- -D warnings

## Run security audit
audit:
	cargo audit

#==============================================================================
# Cleanup
#==============================================================================

## Clean build artifacts
clean:
	cargo clean

## Clean everything (build + docker)
clean-all: clean dev-clean
	@echo "Cleaned all build artifacts and Docker resources"

#==============================================================================
# Installation
#==============================================================================

## Install PAM module system-wide (requires sudo)
install: build
	sudo cp target/release/libpam_unix_oidc.so /lib/security/pam_unix_oidc.so
	@echo "Installed: /lib/security/pam_unix_oidc.so"

## Uninstall PAM module
uninstall:
	sudo rm -f /lib/security/pam_unix_oidc.so
	@echo "Uninstalled PAM module"

#==============================================================================
# Documentation
#==============================================================================

## Build documentation
docs:
	cargo doc --no-deps --all-features

## Open documentation in browser
docs-open: docs
	open target/doc/pam_unix_oidc/index.html 2>/dev/null || \
		xdg-open target/doc/pam_unix_oidc/index.html 2>/dev/null || \
		echo "Open target/doc/pam_unix_oidc/index.html in your browser"

#==============================================================================
# Help
#==============================================================================

## Show this help message
help:
	@echo "unix-oidc Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build:"
	@echo "  build          Build PAM module in Docker (cross-platform)"
	@echo "  build-native   Build natively (Linux with libpam-dev required)"
	@echo "  build-dev      Build in debug mode"
	@echo ""
	@echo "Test:"
	@echo "  test           Run unit tests"
	@echo "  test-verbose   Run unit tests with output"
	@echo "  test-integration  Run integration tests"
	@echo "  test-all       Run all tests (unit + integration)"
	@echo ""
	@echo "Development Environment:"
	@echo "  dev-up         Start Keycloak, LDAP, test-host"
	@echo "  dev-down       Stop test environment"
	@echo "  dev-status     Show environment status"
	@echo "  dev-logs       Follow all service logs"
	@echo "  dev-token      Get a test token from Keycloak"
	@echo ""
	@echo "Code Quality:"
	@echo "  check          Run all quality checks"
	@echo "  lint           Run clippy"
	@echo "  fmt            Format code"
	@echo ""
	@echo "Other:"
	@echo "  clean          Clean build artifacts"
	@echo "  clean-all      Clean build + Docker resources"
	@echo "  install        Install PAM module (sudo required)"
	@echo "  docs           Build documentation"
