# Interplanetary SDK — common developer targets
# Usage: make [target]

CARGO     ?= cargo
FEATURES  ?=
EXAMPLE   ?= three_node

.PHONY: help build release test test-all check fmt fmt-check clippy doc \
        example examples clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

build: ## Build the library (default features)
	$(CARGO) build $(if $(FEATURES),--features $(FEATURES))

release: ## Build optimized release binary
	$(CARGO) build --release $(if $(FEATURES),--features $(FEATURES))

test: ## Run unit and integration tests
	$(CARGO) test $(if $(FEATURES),--features $(FEATURES))

test-all: ## Run tests with all features enabled
	$(CARGO) test --all-features

check: ## Type-check without producing binaries
	$(CARGO) check --all-targets $(if $(FEATURES),--features $(FEATURES))

fmt: ## Format source with rustfmt
	$(CARGO) fmt

fmt-check: ## Check formatting without writing
	$(CARGO) fmt --check

clippy: ## Lint with clippy (deny warnings)
	$(CARGO) clippy --all-targets --all-features -- -D warnings

doc: ## Build API documentation
	$(CARGO) doc --no-deps --all-features --open

example: ## Run an example (EXAMPLE=three_node)
	$(CARGO) run --example $(EXAMPLE)

examples: ## Run all examples
	$(CARGO) run --example three_node
	$(CARGO) run --example three_node_integrated
	$(CARGO) run --example expiry_demo
	$(CARGO) run --example contact_failure_reroute

clean: ## Remove build artifacts
	$(CARGO) clean
