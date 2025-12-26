#!/bin/bash

# test_property.sh - Property-Based Testing Environment Setup
# Uses theft library for property-based testing in C

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/src"
TEST_DIR="${SCRIPT_DIR}/tests"
BUILD_DIR="${SCRIPT_DIR}/build/property"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=== Property-Based Testing Environment Setup ==="

# Create necessary directories
mkdir -p "${BUILD_DIR}"

# Step 1: Check and install theft library
echo -e "${YELLOW}[1] Setting up theft library...${NC}"

THEFT_INSTALLED=0

# Check if theft is already installed via pkg-config
if pkg-config --exists theft 2>/dev/null; then
    echo -e "${GREEN}✓ theft library already installed${NC}"
    THEFT_INSTALLED=1
else
    echo -e "${BLUE}theft library not found, building from source...${NC}"

    # Build from source
    THEFT_DIR="${BUILD_DIR}/theft"

    # Clone if not already cloned
    if [ ! -d "${THEFT_DIR}" ]; then
        echo -e "${BLUE}Cloning theft from GitHub...${NC}"
        git clone https://github.com/silentbicycle/theft.git "${THEFT_DIR}"
    fi

    if [ -d "${THEFT_DIR}" ]; then
        echo -e "${BLUE}Building theft library...${NC}"
        cd "${THEFT_DIR}"
        make clean 2>/dev/null || true
        make

        # Install theft to /usr/local (may require sudo)
        echo -e "${BLUE}Installing theft (may require password)...${NC}"
        sudo make install || {
            echo -e "${YELLOW}⚠ System install failed, using local build${NC}"
        }

        cd "${SCRIPT_DIR}"
        THEFT_INSTALLED=1
        echo -e "${GREEN}✓ theft library built and installed${NC}"
    else
        echo -e "${RED}✗ Failed to clone theft repository${NC}"
        exit 1
    fi
fi

# Set up compiler flags
if pkg-config --exists theft 2>/dev/null; then
    THEFT_CFLAGS=$(pkg-config --cflags theft)
    THEFT_LIBS=$(pkg-config --libs theft)
else
    # Fallback to local build paths
    THEFT_CFLAGS="-I${BUILD_DIR}/theft/inc"
    THEFT_LIBS="-L${BUILD_DIR}/theft -ltheft"
fi

# Step 2: Verify test files exist
echo -e "${YELLOW}[2] Verifying property-based test files...${NC}"

PROPERTY_TEST_FILE="${TEST_DIR}/property/test_property.c"

if [ ! -f "${PROPERTY_TEST_FILE}" ]; then
    echo -e "${RED}✗ Test file not found: ${PROPERTY_TEST_FILE}${NC}"
    echo "Please ensure property tests are in tests/property/test_property.c"
    exit 1
fi

echo -e "${GREEN}✓ Property test file found${NC}"

# Skip the old template creation - using actual theft-based tests now
if false; then
    cat > /dev/null << 'EOF'
#include <theft.h>
#include <stdio.h>
#include <stdlib.h>

// Example: Property-based tests for integer functions
// Uncomment and modify based on your code

/*
// Property: add(a, b) == add(b, a) (commutative)
static theft_trial_res
prop_add_commutative(struct theft *t, theft_seed seed, void *arg) {
    (void)arg;

    // Generate two random integers
    int a = theft_random_choice(t, 100);
    int b = theft_random_choice(t, 100);

    // Check property
    if (add(a, b) != add(b, a)) {
        fprintf(stderr, "Commutativity failed: add(%d, %d) != add(%d, %d)\n",
                a, b, b, a);
        return THEFT_TRIAL_FAIL;
    }

    return THEFT_TRIAL_PASS;
}

// Property: add(a, 0) == a (identity)
static theft_trial_res
prop_add_identity(struct theft *t, theft_seed seed, void *arg) {
    (void)arg;

    int a = theft_random_choice(t, 100);

    if (add(a, 0) != a) {
        fprintf(stderr, "Identity property failed: add(%d, 0) != %d\n", a, a);
        return THEFT_TRIAL_FAIL;
    }

    return THEFT_TRIAL_PASS;
}

// Property: (a + b) + c == a + (b + c) (associativity)
static theft_trial_res
prop_add_associative(struct theft *t, theft_seed seed, void *arg) {
    (void)arg;

    int a = theft_random_choice(t, 50);
    int b = theft_random_choice(t, 50);
    int c = theft_random_choice(t, 50);

    if (add(add(a, b), c) != add(a, add(b, c))) {
        fprintf(stderr, "Associativity failed: (%d + %d) + %d != %d + (%d + %d)\n",
                a, b, c, a, b, c);
        return THEFT_TRIAL_FAIL;
    }

    return THEFT_TRIAL_PASS;
}
*/

int main(int argc, char *argv[]) {
    theft_seed seed = theft_random_seed();
    int errors = 0;

    printf("=== Property-Based Testing ===\n\n");

    // Create property test cases
    // Example below - uncomment and add your properties

    /*
    struct theft_run_config cfg = {
        .prop1 = prop_add_commutative,
        .prop1_name = "add_commutative",
        .trials = 1000,
        .seed = seed,
    };

    enum theft_run_res res = theft_run(&cfg);

    if (res != THEFT_RUN_PASS) {
        printf("Property test failed!\n");
        errors++;
    } else {
        printf("Property test passed!\n");
    }
    */

    printf("\nAdd your property-based tests in %s\n", __FILE__);

    return errors;
}
EOF
fi

# Step 3: Compile property-based tests
echo -e "${YELLOW}[3] Compiling property-based tests...${NC}"

PROPERTY_BINARY="${BUILD_DIR}/property_tests"

# Compile with theft library
if gcc -Wall -Wextra -g -O2 \
    -o "${PROPERTY_BINARY}" \
    "${SRC_DIR}"/*.c \
    "${PROPERTY_TEST_FILE}" \
    ${THEFT_CFLAGS} \
    ${THEFT_LIBS} \
    -I"${SRC_DIR}"; then
    echo -e "${GREEN}✓ Compilation successful${NC}"
else
    echo -e "${RED}✗ Compilation failed${NC}"
    echo "Make sure theft library is properly installed"
    exit 1
fi

# Step 4: Run property-based tests
echo -e "${YELLOW}[4] Running property-based tests...${NC}"

if [ -x "${PROPERTY_BINARY}" ]; then
    echo ""
    if "${PROPERTY_BINARY}"; then
        echo ""
        echo -e "${GREEN}✓ All property tests passed${NC}"
        TEST_RESULT=0
    else
        echo ""
        echo -e "${RED}✗ Some property tests failed${NC}"
        TEST_RESULT=1
    fi
else
    echo -e "${RED}✗ Test binary not executable${NC}"
    TEST_RESULT=1
fi

# Step 5: Generate test report
echo ""
echo "=== Property-Based Testing Report ==="
echo "Test Framework:  theft (property-based testing library)"
echo "Test File:       ${PROPERTY_TEST_FILE}"
echo "Binary:          ${PROPERTY_BINARY}"
echo "Build Dir:       ${BUILD_DIR}"
echo ""
echo -e "${BLUE}theft library features used:${NC}"
echo "  - theft_random_choice(t, max): Generate random integers"
echo "  - theft_run(&config): Execute property tests"
echo "  - Type info with alloc/free callbacks"
echo "  - THEFT_TRIAL_PASS/FAIL/SKIP return values"
echo "  - Automatic test case generation (1000 trials per property)"
echo ""
echo "Documentation: https://github.com/silentbicycle/theft"
echo ""

if [ $TEST_RESULT -eq 0 ]; then
    echo -e "${GREEN}Property-based testing complete - all tests passed!${NC}"
else
    echo -e "${RED}Property-based testing complete - some tests failed!${NC}"
fi

exit $TEST_RESULT
