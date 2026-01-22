.PHONY: pytest hypothesis test help

# Extract arguments after the target name
ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

# Prevent make from treating arguments as targets
$(eval $(ARGS):;@:)

help:
	@echo "Available targets:"
	@echo "  make pytest [TESTCASE]     - Run unit tests (test.py)"
	@echo "  make hypothesis [TESTCASE] - Run property-based tests (pbt.py)"
	@echo "  make test                  - Run all tests"
	@echo ""
	@echo "Examples:"
	@echo "  make pytest                - Run all unit tests"
	@echo "  make pytest test_parser    - Run specific test"
	@echo "  make hypothesis -k test_foo - Run tests matching pattern"

pytest:
	uv run pytest test.py $(ARGS)

hypothesis:
	uv run pytest pbt.py $(ARGS)

test:
	@echo "Running unit tests..."
	uv run pytest test.py
	@echo "\nRunning property-based tests..."
	uv run pytest pbt.py
	@echo "\nRunning symbolic execution..."
