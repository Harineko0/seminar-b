.PHONY: pytest hypothesis crosshair test help

# Extract arguments after the target name
ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

# Prevent make from treating arguments as targets
$(eval $(ARGS):;@:)

help:
	@echo "Available targets:"
	@echo "  make pytest [TESTCASE]     - Run unit tests (test.py)"
	@echo "  make hypothesis [TESTCASE] - Run property-based tests (pbt.py)"
	@echo "  make crosshair [TESTCASE]  - Run symbolic execution (symbolic.py)"
	@echo "  make test                  - Run all tests"
	@echo "  make e2e [ARGS]            - Run end-to-end tests (test_e2e.py, test_e2e_complex.py)"
	@echo ""
	@echo "Examples:"
	@echo "  make pytest                - Run all unit tests"
	@echo "  make pytest test_parser    - Run specific test"
	@echo "  make hypothesis -k test_foo - Run tests matching pattern"

pytest:
	uv run pytest test.py $(ARGS)

hypothesis:
	uv run pytest pbt.py $(ARGS)

crosshair:
	uv run crosshair check symbolic.py $(ARGS)

e2e:
	uv run pytest test_e2e.py $(ARGS)
	uv run pytest test_e2e_complex.py $(ARGS)

test:
	@echo "Running unit tests..."
	uv run pytest test.py
	@echo "\nRunning property-based tests..."
	uv run pytest pbt.py
	@echo "\nRunning symbolic execution..."
	uv run crosshair check symbolic.py
	@echo "\nRunning end-to-end tests..."
	uv run pytest test_e2e.py
	uv run pytest test_e2e_complex.py
