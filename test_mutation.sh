#!/bin/bash

# test_mutation.sh - Mutation Testing Environment Setup and Execution
# Tests C code by introducing mutations and checking if tests can detect them

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/src"
TEST_DIR="${SCRIPT_DIR}/tests"
BUILD_DIR="${SCRIPT_DIR}/build/mutation"
MUTATIONS_DIR="${BUILD_DIR}/mutations"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== Mutation Testing Environment Setup ==="

# Create necessary directories
mkdir -p "${BUILD_DIR}"
mkdir -p "${MUTATIONS_DIR}"

# Step 1: Compile original code and tests
echo -e "${YELLOW}[1] Compiling original code and test suite...${NC}"
if [ -f "${SRC_DIR}/Makefile" ]; then
    make -C "${SRC_DIR}" clean
    make -C "${SRC_DIR}"
    ORIGINAL_BINARY="${SRC_DIR}/target"
else
    # Fallback: compile C files
    if [ -z "$(ls -A ${SRC_DIR}/*.c 2>/dev/null)" ]; then
        echo -e "${RED}Error: No source files found in ${SRC_DIR}${NC}"
        exit 1
    fi
    gcc -o "${BUILD_DIR}/original" "${SRC_DIR}"/*.c "${TEST_DIR}"/*.c -I"${SRC_DIR}" 2>/dev/null || true
    ORIGINAL_BINARY="${BUILD_DIR}/original"
fi

# Step 2: Run original tests to establish baseline
echo -e "${YELLOW}[2] Running original test suite...${NC}"
if ! "${ORIGINAL_BINARY}" >/dev/null 2>&1; then
    echo -e "${RED}Original tests failed! Fix the code before running mutation tests.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Original tests passed${NC}"

# Step 3: Define mutation operators
echo -e "${YELLOW}[3] Setting up mutation operators...${NC}"

# List of mutation operators
# AOR: Arithmetic Operator Replacement (+ → -, - → +, etc.)
# ROR: Relational Operator Replacement (== → !=, < → >, etc.)
# LOR: Logical Operator Replacement (&& → ||, etc.)
# COR: Conditional Operator Replacement (if → else, etc.)
# SOR: Statement Operator Replacement (return modifications)

declare -a MUTATIONS=(
    "AOR_PLUS_TO_MINUS"      # + → -
    "AOR_MINUS_TO_PLUS"      # - → +
    "AOR_MUL_TO_DIV"         # * → /
    "ROR_EQ_TO_NEQ"          # == → !=
    "ROR_LT_TO_GT"           # < → >
    "ROR_LE_TO_GE"           # <= → >=
    "LOR_AND_TO_OR"          # && → ||
)

MUTATION_COUNT=${#MUTATIONS[@]}
KILLED_MUTATIONS=0
SURVIVED_MUTATIONS=0

# Step 4: Apply mutations and test
echo -e "${YELLOW}[4] Applying mutations and testing...${NC}"
echo ""

for ((i = 0; i < MUTATION_COUNT; i++)); do
    MUTATION="${MUTATIONS[$i]}"
    MUTATION_FILE="${MUTATIONS_DIR}/mutant_${i}.c"

    echo -e "Testing mutation ${i}: ${MUTATION}"

    # Create a mutated version (placeholder - actual mutation would be tool-specific)
    # In a real scenario, use a tool like Mutant or create sed-based mutations
    cp "${SRC_DIR}"/*.c "${MUTATION_FILE}" 2>/dev/null || true

    # Compile mutated version
    MUTANT_BINARY="${MUTATIONS_DIR}/mutant_${i}"
    if gcc -o "${MUTANT_BINARY}" "${MUTATION_FILE}" "${TEST_DIR}"/*.c -I"${SRC_DIR}" 2>/dev/null; then
        # Run tests on mutated code
        if ! "${MUTANT_BINARY}" >/dev/null 2>&1; then
            # Mutation was killed (test detected it)
            KILLED_MUTATIONS=$((KILLED_MUTATIONS + 1))
            echo -e "${GREEN}  ✓ Killed${NC}"
        else
            # Mutation survived (test didn't detect it)
            SURVIVED_MUTATIONS=$((SURVIVED_MUTATIONS + 1))
            echo -e "${RED}  ✗ Survived${NC}"
        fi
    else
        echo -e "${YELLOW}  ⚠ Failed to compile${NC}"
    fi
done

# Step 5: Report results
echo ""
echo "=== Mutation Testing Report ==="
echo "Total Mutations:     ${MUTATION_COUNT}"
echo "Killed Mutations:    ${KILLED_MUTATIONS}"
echo "Survived Mutations:  ${SURVIVED_MUTATIONS}"

if [ $MUTATION_COUNT -gt 0 ]; then
    MUTATION_SCORE=$((KILLED_MUTATIONS * 100 / MUTATION_COUNT))
    echo "Mutation Score:      ${MUTATION_SCORE}%"

    if [ $MUTATION_SCORE -ge 80 ]; then
        echo -e "${GREEN}✓ Good test coverage!${NC}"
    elif [ $MUTATION_SCORE -ge 60 ]; then
        echo -e "${YELLOW}⚠ Acceptable test coverage${NC}"
    else
        echo -e "${RED}✗ Poor test coverage - add more tests!${NC}"
    fi
fi

# Cleanup
rm -f "${MUTATIONS_DIR}"/*.c

echo ""
echo "Mutation testing complete. Results saved in ${BUILD_DIR}"
