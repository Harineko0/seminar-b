#!/bin/bash

# test_symbolic.sh - Symbolic Execution Testing with KLEE
# Uses KLEE Docker container for symbolic execution analysis

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/src"
BUILD_DIR="${SCRIPT_DIR}/build/symbolic"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# KLEE Configuration
KLEE_IMAGE="klee/klee:latest"
KLEE_TIMEOUT="30"  # seconds per test
KLEE_MEMORY="2048" # MB

echo "=== Symbolic Execution Testing with KLEE ==="

# Create necessary directories
mkdir -p "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/results"

# Step 1: Check Docker and KLEE image
echo -e "${YELLOW}[1] Checking Docker and KLEE image...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    exit 1
fi

if ! docker image inspect "${KLEE_IMAGE}" >/dev/null 2>&1; then
    echo -e "${RED}Error: KLEE image not found. Pull it with:${NC}"
    echo "  docker pull ${KLEE_IMAGE}"
    exit 1
fi

echo -e "${GREEN}✓ Docker and KLEE image ready${NC}"

# Step 2: Create KLEE test harness template
echo -e "${YELLOW}[2] Setting up KLEE test harness...${NC}"

HARNESS_FILE="${BUILD_DIR}/harness.c"

if [ ! -f "${HARNESS_FILE}" ]; then
    cat > "${HARNESS_FILE}" << 'EOF'
#include <klee/klee.h>
#include <stdio.h>
#include <assert.h>

// Include your header files here
// #include "myprogram.h"

// Example symbolic execution harness
// Modify this based on your actual code

/*
// Example 1: Testing a simple function
int my_function(int a, int b) {
    if (a > b) {
        return a - b;
    } else {
        return b - a;
    }
}

void test_my_function() {
    int x, y;

    // Mark these as symbolic (KLEE will explore all paths)
    klee_make_symbolic(&x, sizeof(x), "x");
    klee_make_symbolic(&y, sizeof(y), "y");

    // Constrain inputs if needed
    klee_assume(x >= 0 && x <= 100);
    klee_assume(y >= 0 && y <= 100);

    int result = my_function(x, y);

    // Check properties that should always hold
    klee_assert(result >= 0);
    klee_assert(result <= 100);
}

int main() {
    test_my_function();
    klee_silent_exit(0);
    return 0;
}
*/

// Example 2: Testing array access
/*
#define ARRAY_SIZE 10

int find_element(int arr[], int size, int target) {
    for (int i = 0; i < size; i++) {
        if (arr[i] == target) {
            return i;
        }
    }
    return -1;
}

void test_array_access() {
    int arr[ARRAY_SIZE];
    int target;

    klee_make_symbolic(arr, sizeof(arr), "arr");
    klee_make_symbolic(&target, sizeof(target), "target");

    int idx = find_element(arr, ARRAY_SIZE, target);

    // Verify: if found, the element must match
    if (idx >= 0 && idx < ARRAY_SIZE) {
        klee_assert(arr[idx] == target);
    }
}

int main() {
    test_array_access();
    klee_silent_exit(0);
    return 0;
}
*/

// Example 3: Buffer overflow detection
/*
void process_string(char *str) {
    char buffer[10];
    int i = 0;

    // This could overflow if str is long
    while (str[i] != '\0') {
        buffer[i] = str[i];
        i++;
    }
    buffer[i] = '\0';
}

void test_string_processing() {
    char str[20];
    klee_make_symbolic(str, sizeof(str), "input_string");

    // KLEE will find if process_string can overflow
    process_string(str);
}

int main() {
    test_string_processing();
    klee_silent_exit(0);
    return 0;
}
*/

int main() {
    printf("KLEE Symbolic Execution Harness\n");
    printf("Add your test cases to this file\n");

    klee_silent_exit(0);
    return 0;
}
EOF
    echo -e "${GREEN}✓ Created harness template at ${HARNESS_FILE}${NC}"
fi

# Step 3: Prepare source files for KLEE
echo -e "${YELLOW}[3] Preparing source files for KLEE...${NC}"

# Copy source files to build directory
if ls "${SRC_DIR}"/*.c >/dev/null 2>&1; then
    cp "${SRC_DIR}"/*.c "${BUILD_DIR}/" 2>/dev/null || true
    cp "${SRC_DIR}"/*.h "${BUILD_DIR}/" 2>/dev/null || true
    echo -e "${GREEN}✓ Source files copied${NC}"
else
    echo -e "${YELLOW}⚠ No source files found in ${SRC_DIR}${NC}"
fi

# Step 4: Compile to LLVM bitcode using KLEE Docker
echo -e "${YELLOW}[4] Compiling to LLVM bitcode (KLEE format)...${NC}"

BITCODE_FILE="${BUILD_DIR}/test.bc"

# Create Dockerfile for compilation
COMPILE_SCRIPT="${BUILD_DIR}/compile.sh"
cat > "${COMPILE_SCRIPT}" << 'EOF'
#!/bin/bash
cd /work

# Compile with KLEE compiler (clang with LLVM instrumentation)
clang -I/work -emit-llvm -c -g -o test.bc harness.c *.c 2>&1

if [ -f test.bc ]; then
    echo "Bitcode compilation successful"
    ls -lh test.bc
else
    echo "Warning: Bitcode compilation may have failed"
fi
EOF

chmod +x "${COMPILE_SCRIPT}"

echo "Running KLEE container for compilation..."
docker run --rm \
    -v "${BUILD_DIR}:/work" \
    "${KLEE_IMAGE}" \
    bash /work/compile.sh

if [ -f "${BITCODE_FILE}" ]; then
    echo -e "${GREEN}✓ LLVM bitcode created${NC}"
else
    echo -e "${YELLOW}⚠ Bitcode file not created (check harness.c syntax)${NC}"
fi

# Step 5: Run KLEE symbolic execution
echo -e "${YELLOW}[5] Running KLEE symbolic execution...${NC}"

RESULTS_DIR="${BUILD_DIR}/results/klee_results"

# Create KLEE execution script
KLEE_SCRIPT="${BUILD_DIR}/run_klee.sh"
cat > "${KLEE_SCRIPT}" << EOF
#!/bin/bash
cd /work

echo "Starting KLEE symbolic execution..."

# Run KLEE with various options
klee \
    --output-dir=results/klee_results \
    --max-time=${KLEE_TIMEOUT} \
    --max-memory=${KLEE_MEMORY} \
    --simplify-sym-indices \
    --search=dfs \
    test.bc 2>&1 || true

echo ""
echo "KLEE execution completed"
echo ""

# Display results if available
if [ -d results/klee_results ]; then
    echo "=== KLEE Results Summary ==="
    echo "Test Cases Generated:"
    find results/klee_results -name "*.ktest" | wc -l
    echo ""
    echo "Covered Instructions:"
    find results/klee_results -name "info" -exec cat {} \; 2>/dev/null | grep -i "covered" || echo "N/A"
fi
EOF

chmod +x "${KLEE_SCRIPT}"

# Run KLEE with mounted volume
docker run --rm \
    --memory="${KLEE_MEMORY}m" \
    -v "${BUILD_DIR}:/work" \
    "${KLEE_IMAGE}" \
    bash /work/run_klee.sh

echo -e "${GREEN}✓ Symbolic execution completed${NC}"

# Step 6: Analyze results
echo -e "${YELLOW}[6] Analyzing KLEE results...${NC}"

if [ -d "${RESULTS_DIR}" ]; then
    KTEST_COUNT=$(find "${RESULTS_DIR}" -name "*.ktest" 2>/dev/null | wc -l)
    echo "Test Cases Generated: ${KTEST_COUNT}"

    if [ -f "${RESULTS_DIR}/info" ]; then
        echo ""
        echo "--- KLEE Execution Info ---"
        cat "${RESULTS_DIR}/info"
    fi

    # Look for errors found by KLEE
    if [ -f "${RESULTS_DIR}/test000001.assert.err" ]; then
        echo -e "${RED}✗ Assertion failures detected!${NC}"
    fi

    if [ -f "${RESULTS_DIR}/test000001.ptr.err" ]; then
        echo -e "${RED}✗ Pointer errors detected!${NC}"
    fi

    if [ -f "${RESULTS_DIR}/test000001.free.err" ]; then
        echo -e "${RED}✗ Memory errors detected!${NC}"
    fi
else
    echo -e "${YELLOW}⚠ No results directory found${NC}"
fi

# Step 7: Display report
echo ""
echo "=== Symbolic Execution Report ==="
echo "Testing Framework:   KLEE (Symbolic Execution Engine)"
echo "KLEE Image:          ${KLEE_IMAGE}"
echo "Build Directory:     ${BUILD_DIR}"
echo "Harness File:        ${HARNESS_FILE}"
echo "Bitcode File:        ${BITCODE_FILE}"
echo "Results Directory:   ${RESULTS_DIR}"
echo ""
echo -e "${BLUE}Configuration:${NC}"
echo "  Timeout:           ${KLEE_TIMEOUT}s per test"
echo "  Memory Limit:      ${KLEE_MEMORY}MB"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Edit ${HARNESS_FILE} to add your test cases"
echo "2. Use klee_make_symbolic() to mark symbolic variables"
echo "3. Use klee_assert() to check properties"
echo "4. Run: $0"
echo ""
echo -e "${BLUE}KLEE Documentation:${NC}"
echo "  Website:  https://klee.github.io/"
echo "  Tutorial: https://klee.github.io/tutorials/"
echo ""

# Cleanup temporary scripts
rm -f "${COMPILE_SCRIPT}" "${KLEE_SCRIPT}"

echo "Symbolic execution testing complete."
