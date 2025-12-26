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

# Check if theft is installed
if ! pkg-config --exists theft 2>/dev/null; then
    echo -e "${BLUE}Installing theft library...${NC}"

    # Try to install via package manager
    if command -v brew &> /dev/null; then
        brew install theft 2>/dev/null || echo -e "${YELLOW}⚠ Brew installation failed, trying from source${NC}"
    elif command -v apt-get &> /dev/null; then
        sudo apt-get install -y libtheft-dev 2>/dev/null || echo -e "${YELLOW}⚠ Apt installation failed${NC}"
    fi

    # Build from source if not installed
    if ! pkg-config --exists theft 2>/dev/null; then
        echo -e "${BLUE}Building theft from source...${NC}"
        THEFT_DIR="${BUILD_DIR}/theft"

        if [ ! -d "${THEFT_DIR}" ]; then
            git clone https://github.com/silentbicycle/theft.git "${THEFT_DIR}" 2>/dev/null || true
        fi

        if [ -d "${THEFT_DIR}" ]; then
            cd "${THEFT_DIR}"
            make build
            THEFT_INSTALLED=1
        fi
    fi
fi

if pkg-config --exists theft 2>/dev/null; then
    THEFT_CFLAGS=$(pkg-config --cflags theft)
    THEFT_LIBS=$(pkg-config --libs theft)
    echo -e "${GREEN}✓ theft library found${NC}"
else
    THEFT_CFLAGS="-I/usr/local/include -I/usr/include"
    THEFT_LIBS="-ltheft"
    echo -e "${YELLOW}⚠ theft library not found, using default paths${NC}"
fi

# Step 2: Create example property-based test file
echo -e "${YELLOW}[2] Creating property-based test structure...${NC}"

PROPERTY_TEST_TEMPLATE="${TEST_DIR}/properties.c"

if [ ! -f "${PROPERTY_TEST_TEMPLATE}" ]; then
    mkdir -p "${TEST_DIR}"
    cat > "${PROPERTY_TEST_TEMPLATE}" << 'EOF'
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
    echo -e "${GREEN}✓ Created template at ${PROPERTY_TEST_TEMPLATE}${NC}"
else
    echo -e "${BLUE}Using existing test file${NC}"
fi

# Step 3: Compile property-based tests
echo -e "${YELLOW}[3] Compiling property-based tests...${NC}"

PROPERTY_BINARY="${BUILD_DIR}/property_tests"

# Collect source files
SOURCE_FILES="${SRC_DIR}"/*.c
if [ -f "${PROPERTY_TEST_TEMPLATE}" ]; then
    SOURCE_FILES="${SOURCE_FILES} ${PROPERTY_TEST_TEMPLATE}"
fi

if gcc -o "${PROPERTY_BINARY}" \
    ${SOURCE_FILES} \
    ${THEFT_CFLAGS} \
    ${THEFT_LIBS} \
    -I"${SRC_DIR}" \
    2>/dev/null; then
    echo -e "${GREEN}✓ Compilation successful${NC}"
else
    echo -e "${YELLOW}⚠ Compilation had warnings/errors (check if theft is properly installed)${NC}"
fi

# Step 4: Run property-based tests
echo -e "${YELLOW}[4] Running property-based tests...${NC}"

if [ -x "${PROPERTY_BINARY}" ]; then
    echo ""
    if "${PROPERTY_BINARY}"; then
        echo -e "${GREEN}✓ All property tests passed${NC}"
    else
        echo -e "${RED}✗ Some property tests failed${NC}"
    fi
else
    echo -e "${RED}✗ Test binary not executable${NC}"
fi

# Step 5: Generate test report
echo ""
echo "=== Property-Based Testing Report ==="
echo "Test Framework:  theft (property-based testing library)"
echo "Test File:       ${PROPERTY_TEST_TEMPLATE}"
echo "Binary:          ${PROPERTY_BINARY}"
echo "Build Dir:       ${BUILD_DIR}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Implement your test functions in ${PROPERTY_TEST_TEMPLATE}"
echo "2. Generate random test data using theft_random_* functions"
echo "3. Define properties your code should satisfy"
echo "4. Run: ${PROPERTY_BINARY}"
echo ""
echo -e "${BLUE}Helpful theft functions:${NC}"
echo "  - theft_random_choice(t, max): Generate random integer 0..max"
echo "  - theft_random_bits(t, bits): Generate random bits"
echo "  - theft_trial_pass/fail: Return test result"
echo "  - theft_run(): Execute test with property"
echo ""
echo "Documentation: https://github.com/silentbicycle/theft"

echo ""
echo "Property-based testing setup complete."
