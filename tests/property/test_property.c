#include <stdio.h>
#include <assert.h>
#include <setjmp.h>
#include "math_utils.h"

// Property-Based Testing with theft Library
// Tests mathematical properties that should always hold

// Global jump buffer for handling assertion failures
static jmp_buf jump_buffer;

// Properties for add()
void test_add_properties() {
    printf("=== Testing add() properties ===\n");

    int a, b, c;

    // Property 1: Commutativity - add(a, b) == add(b, a)
    printf("Testing commutativity: a + b == b + a\n");
    for (a = -10; a <= 10; a++) {
        for (b = -10; b <= 10; b++) {
            int result1 = add(a, b);
            int result2 = add(b, a);
            assert(result1 == result2 && "Commutativity violated!");
        }
    }
    printf("✓ Commutativity property holds\n\n");

    // Property 2: Associativity - (a + b) + c == a + (b + c)
    printf("Testing associativity: (a + b) + c == a + (b + c)\n");
    for (a = -5; a <= 5; a++) {
        for (b = -5; b <= 5; b++) {
            for (c = -5; c <= 5; c++) {
                int result1 = add(add(a, b), c);
                int result2 = add(a, add(b, c));
                assert(result1 == result2 && "Associativity violated!");
            }
        }
    }
    printf("✓ Associativity property holds\n\n");

    // Property 3: Identity - add(a, 0) == a
    printf("Testing identity: a + 0 == a\n");
    for (a = -100; a <= 100; a += 10) {
        int result = add(a, 0);
        assert(result == a && "Identity property violated!");
    }
    printf("✓ Identity property holds\n\n");

    // Property 4: Inverse - add(a, -a) == 0
    printf("Testing inverse: a + (-a) == 0\n");
    for (a = -50; a <= 50; a += 5) {
        int result = add(a, -a);
        assert(result == 0 && "Inverse property violated!");
    }
    printf("✓ Inverse property holds\n\n");
}

// Properties for multiply()
void test_multiply_properties() {
    printf("=== Testing multiply() properties ===\n");

    int a, b, c;

    // Property 1: Commutativity - a * b == b * a
    printf("Testing commutativity: a * b == b * a\n");
    for (a = -5; a <= 5; a++) {
        for (b = -5; b <= 5; b++) {
            int result1 = multiply(a, b);
            int result2 = multiply(b, a);
            assert(result1 == result2 && "Commutativity violated!");
        }
    }
    printf("✓ Commutativity property holds\n\n");

    // Property 2: Associativity - (a * b) * c == a * (b * c)
    printf("Testing associativity: (a * b) * c == a * (b * c)\n");
    for (a = -3; a <= 3; a++) {
        for (b = -3; b <= 3; b++) {
            for (c = -3; c <= 3; c++) {
                int result1 = multiply(multiply(a, b), c);
                int result2 = multiply(a, multiply(b, c));
                assert(result1 == result2 && "Associativity violated!");
            }
        }
    }
    printf("✓ Associativity property holds\n\n");

    // Property 3: Identity - a * 1 == a
    printf("Testing multiplicative identity: a * 1 == a\n");
    for (a = -100; a <= 100; a += 20) {
        int result = multiply(a, 1);
        assert(result == a && "Identity property violated!");
    }
    printf("✓ Multiplicative identity property holds\n\n");

    // Property 4: Absorbing element - a * 0 == 0
    printf("Testing absorbing element: a * 0 == 0\n");
    for (a = -100; a <= 100; a += 25) {
        int result = multiply(a, 0);
        assert(result == 0 && "Absorbing element property violated!");
    }
    printf("✓ Absorbing element property holds\n\n");

    // Property 5: Distributivity - a * (b + c) == (a * b) + (a * c)
    printf("Testing distributivity: a * (b + c) == (a * b) + (a * c)\n");
    for (a = -4; a <= 4; a++) {
        for (b = -4; b <= 4; b++) {
            for (c = -4; c <= 4; c++) {
                int result1 = multiply(a, add(b, c));
                int result2 = add(multiply(a, b), multiply(a, c));
                assert(result1 == result2 && "Distributivity violated!");
            }
        }
    }
    printf("✓ Distributivity property holds\n\n");
}

// Properties for max_value() and min_value()
void test_minmax_properties() {
    printf("=== Testing max_value() and min_value() properties ===\n");

    int a, b;

    // Property 1: max(a, b) >= a and max(a, b) >= b
    printf("Testing max >= both inputs\n");
    for (a = -10; a <= 10; a += 2) {
        for (b = -10; b <= 10; b += 2) {
            int result = max_value(a, b);
            assert(result >= a && result >= b && "Max property violated!");
        }
    }
    printf("✓ Max property holds\n\n");

    // Property 2: min(a, b) <= a and min(a, b) <= b
    printf("Testing min <= both inputs\n");
    for (a = -10; a <= 10; a += 2) {
        for (b = -10; b <= 10; b += 2) {
            int result = min_value(a, b);
            assert(result <= a && result <= b && "Min property violated!");
        }
    }
    printf("✓ Min property holds\n\n");

    // Property 3: max(a, b) == max(b, a)
    printf("Testing max commutativity\n");
    for (a = -10; a <= 10; a += 3) {
        for (b = -10; b <= 10; b += 3) {
            assert(max_value(a, b) == max_value(b, a) && "Max commutativity violated!");
        }
    }
    printf("✓ Max commutativity property holds\n\n");

    // Property 4: min(a, b) == min(b, a)
    printf("Testing min commutativity\n");
    for (a = -10; a <= 10; a += 3) {
        for (b = -10; b <= 10; b += 3) {
            assert(min_value(a, b) == min_value(b, a) && "Min commutativity violated!");
        }
    }
    printf("✓ Min commutativity property holds\n\n");
}

// Properties for abs_value()
void test_abs_properties() {
    printf("=== Testing abs_value() properties ===\n");

    int a;

    // Property 1: abs(a) >= 0
    printf("Testing non-negativity: abs(a) >= 0\n");
    for (a = -100; a <= 100; a += 10) {
        int result = abs_value(a);
        assert(result >= 0 && "Non-negativity violated!");
    }
    printf("✓ Non-negativity property holds\n\n");

    // Property 2: abs(-a) == abs(a)
    printf("Testing symmetry: abs(-a) == abs(a)\n");
    for (a = -100; a <= 100; a += 10) {
        int result1 = abs_value(a);
        int result2 = abs_value(-a);
        assert(result1 == result2 && "Symmetry violated!");
    }
    printf("✓ Symmetry property holds\n\n");

    // Property 3: abs(0) == 0
    printf("Testing zero property\n");
    int result = abs_value(0);
    assert(result == 0 && "Zero property violated!");
    printf("✓ Zero property holds\n\n");
}

// Properties for factorial()
void test_factorial_properties() {
    printf("=== Testing factorial() properties ===\n");

    // Property 1: factorial(n) >= 1 for n >= 0
    printf("Testing positivity: factorial(n) >= 1 for n >= 0\n");
    for (int n = 0; n <= 10; n++) {
        int result = factorial(n);
        assert(result >= 1 && "Positivity violated!");
    }
    printf("✓ Positivity property holds\n\n");

    // Property 2: factorial(n) = n * factorial(n-1)
    printf("Testing recursive property: n! = n * (n-1)!\n");
    for (int n = 2; n <= 10; n++) {
        int result1 = factorial(n);
        int result2 = multiply(n, factorial(n - 1));
        assert(result1 == result2 && "Recursive property violated!");
    }
    printf("✓ Recursive property holds\n\n");

    // Property 3: factorial(0) == 1
    printf("Testing base case: 0! == 1\n");
    assert(factorial(0) == 1 && "Base case violated!");
    printf("✓ Base case property holds\n\n");
}

// Properties for fibonacci()
void test_fibonacci_properties() {
    printf("=== Testing fibonacci() properties ===\n");

    // Property 1: fibonacci(n) >= 0 for n >= 0
    printf("Testing non-negativity: fib(n) >= 0 for n >= 0\n");
    for (int n = 0; n <= 15; n++) {
        int result = fibonacci(n);
        assert(result >= 0 && "Non-negativity violated!");
    }
    printf("✓ Non-negativity property holds\n\n");

    // Property 2: fib(n) = fib(n-1) + fib(n-2) for n >= 2
    printf("Testing recursive property: fib(n) = fib(n-1) + fib(n-2)\n");
    for (int n = 2; n <= 15; n++) {
        int result1 = fibonacci(n);
        int result2 = add(fibonacci(n - 1), fibonacci(n - 2));
        assert(result1 == result2 && "Recursive property violated!");
    }
    printf("✓ Recursive property holds\n\n");

    // Property 3: fib(0) == 0, fib(1) == 1
    printf("Testing base cases: fib(0) == 0 && fib(1) == 1\n");
    assert(fibonacci(0) == 0 && fibonacci(1) == 1 && "Base cases violated!");
    printf("✓ Base cases property holds\n\n");
}

int main() {
    printf("========================================\n");
    printf("  Property-Based Testing Suite\n");
    printf("========================================\n\n");

    int failed = 0;

    // Run all property tests
    if (setjmp(jump_buffer) == 0) {
        test_add_properties();
    } else {
        printf("✗ Add properties test failed\n\n");
        failed = 1;
    }

    if (setjmp(jump_buffer) == 0) {
        test_multiply_properties();
    } else {
        printf("✗ Multiply properties test failed\n\n");
        failed = 1;
    }

    if (setjmp(jump_buffer) == 0) {
        test_minmax_properties();
    } else {
        printf("✗ Min/Max properties test failed\n\n");
        failed = 1;
    }

    if (setjmp(jump_buffer) == 0) {
        test_abs_properties();
    } else {
        printf("✗ Abs properties test failed\n\n");
        failed = 1;
    }

    if (setjmp(jump_buffer) == 0) {
        test_factorial_properties();
    } else {
        printf("✗ Factorial properties test failed\n\n");
        failed = 1;
    }

    if (setjmp(jump_buffer) == 0) {
        test_fibonacci_properties();
    } else {
        printf("✗ Fibonacci properties test failed\n\n");
        failed = 1;
    }

    printf("========================================\n");
    if (failed == 0) {
        printf("✓ All property tests passed!\n");
    } else {
        printf("✗ Some property tests failed!\n");
    }
    printf("========================================\n");

    return failed;
}
