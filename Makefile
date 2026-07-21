# Sentinel AI - Makefile for common development tasks

.PHONY: help build test lint fmt check docs clean install dev release

# Default target
help:
	@echo "Sentinel AI - Development Commands"
	@echo ""
	@echo "Core Commands:"
	@echo "  build       - Build all crates in release mode"
	@echo "  test        - Run all tests"
	@echo "  lint        - Run clippy with strict warnings"
	@echo "  fmt         - Format code with rustfmt"
	@echo "  check       - Run all checks (fmt, lint, test)"
	@echo "  docs        - Generate documentation"
	@echo ""
	@echo "Development:"
	@echo "  dev         - Start development environment with Docker Compose"
	@echo "  dev-logs    - Follow development logs"
	@echo "  dev-down    - Stop development environment"
	@echo ""
	@echo "Release:"
	@echo "  release     - Build release artifacts"
	@echo "  package     - Create distribution packages"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean       - Clean build artifacts"
	@echo "  update      - Update dependencies"
	@echo "  audit       - Run security audit"
	@echo "  deny        - Run cargo-deny checks"

# Build all crates in release mode
build:
	cargo build --release --workspace --locked

# Run all tests
test:
	cargo test --workspace --locked

# Run clippy
lint:
	cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

# Format code
fmt:
	cargo fmt --all --check

# Run all checks
check: fmt lint test

# Generate documentation
docs:
	cargo doc --workspace --no-deps --document-private-items

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/

# Update dependencies
update:
	cargo update --workspace

# Security audit
audit:
	cargo audit

# Cargo deny checks
deny:
	cargo deny check

# Development environment
dev:
	docker compose -f docker/docker-compose.yml up -d

dev-logs:
	docker compose -f docker/docker-compose.yml logs -f

dev-down:
	docker compose -f docker/docker-compose.yml down

# Build release artifacts
release:
	cargo build --release --workspace --locked --bins
	./scripts/package-release.sh

# Install locally
install:
	cargo install --path apps/sentinel-core-service --locked --force
	cargo install --path apps/sentinel-cli --locked --force

# Run development server with hot reload
watch:
	cargo watch -x "run --bin sentinel-core-service"

# Generate protobuf code
generate-proto:
	cd crates/sentinel-events && cargo build

# Run integration tests
integration-test:
	cargo test --test integration --workspace --locked

# Benchmark
bench:
	cargo bench --workspace --locked

# Package for distribution
package:
	./scripts/package-all.sh

# CI simulation locally
ci-local: check audit deny

# Verify formatting and linting
verify: fmt lint

# Show outdated dependencies
outdated:
	cargo outdated --workspace --exit-code 1