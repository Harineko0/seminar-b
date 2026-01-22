.PHONY: pytest crosshair test help

# Extract arguments after the target name
ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

# Prevent make from treating arguments as targets
$(eval $(ARGS):;@:)

help:
	@echo "Available targets:"
	@echo "  make pytest [TESTCASE]     - Run unit tests (test.py)"
	@echo "  make crosshair [TESTCASE]  - Run symbolic execution (symbolic.py)"
	@echo "  make test                  - Run all tests"
	@echo ""
	@echo "Examples:"
	@echo "  make pytest                - Run all unit tests"
	@echo "  make pytest test_parser    - Run specific test"

pytest:
	uv run pytest test.py $(ARGS)

crosshair:
	uv run crosshair check symbolic.py $(ARGS)

test:
	@echo "Running unit tests..."
	uv run pytest test.py
	@echo "\nRunning symbolic execution..."
	uv run crosshair check symbolic.py
