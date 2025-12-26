# Software Testing Study - Mutation, Property-Based, and Symbolic Execution

This repository contains templates and frameworks for three different software testing approaches in C:

1. **Mutation Testing** - Introduce mutations into code and verify tests can detect them
2. **Property-Based Testing** - Use the `theft` library to verify mathematical properties
3. **Symbolic Execution** - Use KLEE to automatically explore code paths

## Project Structure

```
seminar-b/
├── src/                          # Source code to be tested
│   ├── math_utils.h             # Header file with function declarations
│   └── math_utils.c             # Implementation of utility functions
│
├── tests/                        # Test suites
│   ├── mutation/
│   │   └── test_mutation.c      # Mutation testing test suite
│   ├── property/
│   │   └── test_property.c      # Property-based testing suite
│   └── symbolic/
│       └── test_symbolic.c      # Symbolic execution test suite
│
├── build/                        # Build artifacts (created at runtime)
│   ├── mutation/                # Mutation testing binaries
│   ├── property/                # Property-based testing binaries
│   └── symbolic/                # Symbolic execution binaries
│
├── test_mutation.sh             # Mutation testing framework script
├── test_property.sh             # Property-based testing framework script
├── test_symbolic.sh             # Symbolic execution framework script
├── Makefile                     # Build configuration
└── README.md                    # This file
```

## Quick Start

### 1. Compile and Run Locally-Compilable Tests with Make

```bash
# Build mutation and property tests
make all

# Run individual tests
make mutation-run      # Compile and run mutation tests
make property-run      # Compile and run property tests

# Run all locally-compilable tests
make run

# Clean build artifacts
make clean

# Show help
make help
```

### 2. Symbolic Execution Testing with Docker

Symbolic execution tests require KLEE, which is only available in Docker. Use the dedicated script:

```bash
# Requires: Docker with KLEE image
# docker pull klee/klee:latest

./test_symbolic.sh     # Setup, compile, and run KLEE symbolic execution
```

### 3. Interactive Framework Scripts

For more detailed testing with frameworks:

```bash
# Run mutation testing framework
./test_mutation.sh

# Run property-based testing framework (uses theft library)
./test_property.sh

# Run symbolic execution framework (requires Docker + KLEE)
./test_symbolic.sh
```

## Testing Approaches

### Mutation Testing (`test_mutation.sh` & `tests/mutation/test_mutation.c`)

**What it does:**
- Introduces mutations (small code changes) into your source code
- Runs your test suite against each mutant
- Reports which mutations are "killed" (test detected the change) vs "survived" (test missed it)
- Calculates mutation score: (killed mutations / total mutations) × 100%

**How it works:**
```
Original Code → Test Suite → Tests Pass (baseline)
    ↓
For each mutation:
  Mutated Code → Test Suite → Test Passes? → Killed/Survived
```

**Mutation Operators Implemented:**
- AOR (Arithmetic Operator Replacement): `+` → `-`, `*` → `/`, etc.
- ROR (Relational Operator Replacement): `==` → `!=`, `<` → `>`, etc.
- LOR (Logical Operator Replacement): `&&` → `||`, etc.

**Example Test:**
```c
TEST("add(2, 3) == 5", add(2, 3) == 5);
TEST("add(3, 7) == add(7, 3)", add(3, 7) == add(7, 3));  // Commutativity
```

**Running:**
```bash
./test_mutation.sh        # Run framework
make mutation-run         # Compile and run test suite
```

---

### Property-Based Testing (`test_property.sh` & `tests/property/test_property.c`)

**What it does:**
- Generates random test inputs to verify mathematical properties
- Tests that properties hold for many different input combinations
- Shrinks counterexamples when a property fails

**Properties Tested:**
1. **Commutativity**: `add(a,b) == add(b,a)`
2. **Associativity**: `(a+b)+c == a+(b+c)`
3. **Identity**: `add(a,0) == a` and `a*1 == a`
4. **Distributivity**: `a*(b+c) == a*b + a*c`
5. **Correctness**: Properties that should always hold

**How it works:**
```
Property Definition → Generate Random Inputs → Verify Property → Report Results
```

**Requirements:**
- `theft` library (auto-installed by `test_property.sh`)

**Example Property:**
```c
// Property: add(a,b) == add(b,a)
for (a = -100; a <= 100; a++) {
    for (b = -100; b <= 100; b++) {
        assert(add(a, b) == add(b, a));
    }
}
```

**Running:**
```bash
./test_property.sh       # Setup and run framework
make property-run        # Compile and run test suite
```

---

### Symbolic Execution (`test_symbolic.sh` & `tests/symbolic/test_symbolic.c`)

**What it does:**
- Executes code with symbolic inputs instead of concrete values
- Automatically explores all possible execution paths
- Finds edge cases and assertion violations
- Generates test cases that trigger specific code paths

**How it works:**
```
Source Code → Compile to LLVM Bitcode → KLEE Symbolic Execution → Test Cases + Coverage
```

**Key KLEE Functions Used:**
- `klee_make_symbolic(ptr, size, name)`: Mark variable as symbolic
- `klee_assume(condition)`: Add constraint on symbolic values
- `klee_assert(condition)`: Check property that should always hold

**Example Test:**
```c
int a, b;
klee_make_symbolic(&a, sizeof(a), "a");
klee_make_symbolic(&b, sizeof(b), "b");

int result = add(a, b);
klee_assert(result == a + b);  // KLEE will verify this
```

**Requirements:**
- Docker with KLEE image installed:
  ```bash
  docker pull klee/klee:latest
  ```

**Important Note:**
Symbolic execution tests must be compiled and run inside the KLEE Docker container (not with standard GCC). The test files include `<klee/klee.h>` which is only available in KLEE's container environment.

**Running:**
```bash
./test_symbolic.sh       # Setup and run KLEE framework (requires Docker)
```

⚠️ **Do NOT use `make symbolic-run`** - Symbolic tests require KLEE and must be run through the Docker script.

---

## Source Code: math_utils

The `src/math_utils.c` file provides simple mathematical functions for testing:

- `add(a, b)` - Addition
- `subtract(a, b)` - Subtraction
- `multiply(a, b)` - Multiplication
- `abs_value(x)` - Absolute value
- `max_value(a, b)` - Maximum of two numbers
- `min_value(a, b)` - Minimum of two numbers
- `is_even(x)` - Check if even (1) or odd (0)
- `is_positive(x)` - Check if positive (1) or not (0)
- `factorial(n)` - Factorial (0 to 10)
- `fibonacci(n)` - Fibonacci number (0-indexed)

## Adding Your Own Code

To test your own C code:

1. **Add source files** to `src/`:
   ```bash
   src/your_code.h
   src/your_code.c
   ```

2. **Create mutation tests** in `tests/mutation/test_mutation.c`:
   ```c
   TEST("your_function(x) should return y", your_function(x) == y);
   ```

3. **Create property tests** in `tests/property/test_property.c`:
   ```c
   for (a = -100; a <= 100; a++) {
       assert(property_holds(a));
   }
   ```

4. **Create symbolic tests** in `tests/symbolic/test_symbolic.c`:
   ```c
   int x;
   klee_make_symbolic(&x, sizeof(x), "x");
   klee_assert(property_holds(x));
   ```

5. **Update Makefile** if needed (only for mutation and property tests):
   ```makefile
   SOURCE_FILES = $(SRC_DIR)/math_utils.c $(SRC_DIR)/your_code.c
   ```

**Note on Symbolic Tests:**
If you add symbolic execution tests, they can only be compiled and run through `./test_symbolic.sh` (requires Docker with KLEE). They cannot be compiled with the Makefile.

## Understanding Test Results

### Mutation Testing Report
```
Total Mutations:     10
Killed Mutations:    8      (tests detected the mutation)
Survived Mutations:  2      (tests missed the mutation)
Mutation Score:      80%
```
- **80%+**: Good test coverage
- **60-80%**: Acceptable coverage
- **<60%**: Poor coverage - add more tests

### Property Testing Report
```
✓ Commutativity property holds
✓ Associativity property holds
✓ Identity property holds
...
✓ All property tests passed!
```

### Symbolic Execution Report (KLEE)
```
Test Cases Generated: 15
Covered Instructions: 287/320
Errors Found:
  - assertion failures
  - pointer errors
  - buffer overflows
```

## Dependencies

### Required
- GCC or Clang
- Make

### Optional (for specific testing types)
- **Property-Based Testing**: `theft` library (auto-installed)
- **Symbolic Execution**: Docker + KLEE image
  ```bash
  docker pull klee/klee:latest
  ```

## Troubleshooting

### `make symbolic-run` fails
**Error:** `fatal error: 'klee/klee.h' file not found`

**Solution:** Symbolic tests require KLEE and can only be compiled in the KLEE Docker container. Use the script instead:
```bash
./test_symbolic.sh
```

### `./test_symbolic.sh` fails
**Error:** `Error: Docker is not installed` or `Error: KLEE image not found`

**Solution:** Install Docker and pull the KLEE image:
```bash
docker pull klee/klee:latest
```

### Property tests fail to compile
**Error:** Related to `theft` library

**Solution:** The `test_property.sh` script auto-installs theft. If it still fails:
```bash
make clean
./test_property.sh    # Let it setup and install theft
```

## Further Reading

- [Mutation Testing](https://en.wikipedia.org/wiki/Mutation_testing)
- [Property-Based Testing](https://hypothesis.works/)
- [KLEE Documentation](https://klee.github.io/)
- [theft Library](https://github.com/silentbicycle/theft)

## License

This is an educational project for a software testing seminar.
