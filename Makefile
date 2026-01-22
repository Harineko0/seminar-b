.PHONY: pytest hypothesis help

# Extract arguments after the target name
ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

# Prevent make from treating arguments as targets
$(eval $(ARGS):;@:)

help:
	@echo "Available targets:"
	@echo "  make hypothesis [TESTCASE] - Run property-based tests (pbt.py)"
	@echo ""
	@echo "Examples:"
	@echo "  make hypothesis -k test_foo - Run tests matching pattern"

hypothesis:
	uv run pytest pbt.py $(ARGS)

