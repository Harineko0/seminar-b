.PHONY: pytest crosshair help

# Extract arguments after the target name
ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

# Prevent make from treating arguments as targets
$(eval $(ARGS):;@:)

help:
	@echo "Available targets:"
	@echo "  make crosshair [TESTCASE]  - Run symbolic execution (crosshair_contracts.py)"
	@echo "  make test                   - Run concrete tests (symbolic.py)"

crosshair:
	uv run crosshair check crosshair_contracts.py $(ARGS)

test:
	uv run python3 symbolic.py
