.PHONY: pytest crosshair help

# Extract arguments after the target name
ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

# Prevent make from treating arguments as targets
$(eval $(ARGS):;@:)

help:
	@echo "Available targets:"
	@echo "  make crosshair [TESTCASE]  - Run symbolic execution (symbolic.py)"

crosshair:
	uv run crosshair check symbolic.py $(ARGS)
