.PHONY: all clean mutation property symbolic mutation-run property-run symbolic-run help

# Directories
SRC_DIR = src
TESTS_DIR = tests
BUILD_DIR = build
MUTATION_TEST_DIR = $(TESTS_DIR)/mutation
PROPERTY_TEST_DIR = $(TESTS_DIR)/property
SYMBOLIC_TEST_DIR = $(TESTS_DIR)/symbolic

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g -O2
INCLUDES = -I$(SRC_DIR)

# Targets
MUTATION_BIN = $(BUILD_DIR)/mutation/test_mutation
PROPERTY_BIN = $(BUILD_DIR)/property/test_property
SYMBOLIC_BIN = $(BUILD_DIR)/symbolic/test_symbolic

# Source files
SOURCE_FILES = $(SRC_DIR)/math_utils.c

all: mutation property

help:
	@echo "Mutation Testing Study - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  make mutation       - Build mutation test"
	@echo "  make property       - Build property test"
	@echo "  make mutation-run   - Build and run mutation test"
	@echo "  make property-run   - Build and run property test"
	@echo "  make all            - Build all tests (mutation + property)"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "Framework scripts (for interactive testing):"
	@echo "  ./test_mutation.sh  - Run mutation testing framework"
	@echo "  ./test_property.sh  - Run property-based testing framework"
	@echo "  ./test_symbolic.sh  - Run symbolic execution (KLEE) framework (requires Docker)"
	@echo ""
	@echo "Note: Symbolic execution tests must be run via ./test_symbolic.sh"
	@echo "      (requires Docker with KLEE image: docker pull klee/klee:latest)"

# Create build directories
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)/mutation
	@mkdir -p $(BUILD_DIR)/property
	@mkdir -p $(BUILD_DIR)/symbolic

# Mutation testing
mutation: $(BUILD_DIR) $(MUTATION_BIN)

$(MUTATION_BIN): $(SOURCE_FILES) $(MUTATION_TEST_DIR)/test_mutation.c
	@echo "Compiling mutation tests..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^
	@echo "✓ Mutation test compiled: $@"

mutation-run: mutation
	@echo ""
	@echo "Running mutation tests..."
	@echo "=========================================="
	@$(MUTATION_BIN)
	@echo "=========================================="

# Property-based testing
property: $(BUILD_DIR) $(PROPERTY_BIN)

$(PROPERTY_BIN): $(SOURCE_FILES) $(PROPERTY_TEST_DIR)/test_property.c
	@echo "Compiling property tests..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^
	@echo "✓ Property test compiled: $@"

property-run: property
	@echo ""
	@echo "Running property tests..."
	@echo "=========================================="
	@$(PROPERTY_BIN)
	@echo "=========================================="

# Symbolic execution testing
# Note: Symbolic tests must be compiled and run through KLEE Docker container
# Use: ./test_symbolic.sh

# Run all locally-compilable tests
run: mutation-run property-run
	@echo ""
	@echo "For symbolic execution testing, run: ./test_symbolic.sh"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "✓ Cleaned"
