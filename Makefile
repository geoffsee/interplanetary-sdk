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
	$(CARGO) build -p interplanetary-sdk $(if $(FEATURES),--features $(FEATURES))

release: ## Build optimized release binary
	$(CARGO) build -p interplanetary-sdk --release $(if $(FEATURES),--features $(FEATURES))

test: ## Run unit and integration tests
	$(CARGO) test -p interplanetary-sdk $(if $(FEATURES),--features $(FEATURES))

test-all: ## Run tests with all features enabled
	$(CARGO) test --workspace --all-features

check: ## Type-check without producing binaries
	$(CARGO) check -p interplanetary-sdk --all-targets $(if $(FEATURES),--features $(FEATURES))

fmt: ## Format source with rustfmt
	$(CARGO) fmt

fmt-check: ## Check formatting without writing
	$(CARGO) fmt --check

clippy: ## Lint with clippy (deny warnings)
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

doc: ## Build API documentation
	$(CARGO) doc -p interplanetary-sdk --no-deps --all-features --open

example: ## Run an example (EXAMPLE=three_node, optional FEATURES=)
	$(CARGO) run -p interplanetary-sdk --example $(EXAMPLE) $(if $(FEATURES),--features $(FEATURES))

examples: ## Run all examples
	$(CARGO) run -p interplanetary-sdk --example three_node
	$(CARGO) run -p interplanetary-sdk --example three_node_integrated
	$(CARGO) run -p interplanetary-sdk --example expiry_demo
	$(CARGO) run -p interplanetary-sdk --example contact_failure_reroute

clean: ## Remove build artifacts
	$(CARGO) clean
