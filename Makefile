.PHONY: hypothesis crosshair test help

# Extract arguments after the target name
ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

# Prevent make from treating arguments as targets
$(eval $(ARGS):;@:)

help:
	@echo "Available targets:"
	@echo "  make hypothesis [TESTCASE] - Run property-based tests (pbt.py)"
	@echo "  make crosshair [TESTCASE]  - Run symbolic execution (symbolic.py)"
	@echo "  make test                  - Run all tests"
	@echo ""
	@echo "Examples:"
	@echo "  make hypothesis -k test_foo - Run tests matching pattern"

hypothesis:
	uv run pytest pbt.py $(ARGS)

crosshair:
	uv run crosshair check symbolic.py $(ARGS)

test:
	@echo "\nRunning symbolic execution..."
	uv run crosshair check symbolic.py
