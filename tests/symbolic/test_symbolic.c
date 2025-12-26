#include <klee/klee.h>
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include "math_utils.h"

// Symbolic Execution Testing with KLEE
// Tests code paths and finds edge cases automatically

// ========== Test 1: add() with symbolic inputs ==========
void test_add_symbolic() {
    printf("Testing add() with symbolic inputs\n");

    int a, b;
    klee_make_symbolic(&a, sizeof(a), "a");
    klee_make_symbolic(&b, sizeof(b), "b");

    // Constrain to reasonable range
    klee_assume(a >= -100 && a <= 100);
    klee_assume(b >= -100 && b <= 100);

    int result = add(a, b);

    // Property: result should be sum of inputs
    klee_assert(result == a + b);
}

// ========== Test 2: subtract() with symbolic inputs ==========
void test_subtract_symbolic() {
    printf("Testing subtract() with symbolic inputs\n");

    int a, b;
    klee_make_symbolic(&a, sizeof(a), "a");
    klee_make_symbolic(&b, sizeof(b), "b");

    klee_assume(a >= -100 && a <= 100);
    klee_assume(b >= -100 && b <= 100);

    int result = subtract(a, b);

    // Property: result should be difference
    klee_assert(result == a - b);
}

// ========== Test 3: multiply() with symbolic inputs ==========
void test_multiply_symbolic() {
    printf("Testing multiply() with symbolic inputs\n");

    int a, b;
    klee_make_symbolic(&a, sizeof(a), "a");
    klee_make_symbolic(&b, sizeof(b), "b");

    klee_assume(a >= -50 && a <= 50);
    klee_assume(b >= -50 && b <= 50);

    int result = multiply(a, b);

    // Property: result should be product
    klee_assert(result == a * b);

    // Commutative property
    klee_assert(multiply(a, b) == multiply(b, a));
}

// ========== Test 4: abs_value() with symbolic input ==========
void test_abs_symbolic() {
    printf("Testing abs_value() with symbolic input\n");

    int a;
    klee_make_symbolic(&a, sizeof(a), "a");

    int result = abs_value(a);

    // Property 1: Result is non-negative
    klee_assert(result >= 0);

    // Property 2: abs(-a) == abs(a)
    klee_assert(abs_value(a) == abs_value(-a));

    // Property 3: abs(a) >= a (always)
    klee_assert(result >= a);
}

// ========== Test 5: max_value() with symbolic inputs ==========
void test_max_symbolic() {
    printf("Testing max_value() with symbolic inputs\n");

    int a, b;
    klee_make_symbolic(&a, sizeof(a), "a");
    klee_make_symbolic(&b, sizeof(b), "b");

    int result = max_value(a, b);

    // Property 1: Result >= both inputs
    klee_assert(result >= a);
    klee_assert(result >= b);

    // Property 2: Result equals one of the inputs
    klee_assert(result == a || result == b);

    // Property 3: Commutativity
    klee_assert(max_value(a, b) == max_value(b, a));
}

// ========== Test 6: min_value() with symbolic inputs ==========
void test_min_symbolic() {
    printf("Testing min_value() with symbolic inputs\n");

    int a, b;
    klee_make_symbolic(&a, sizeof(a), "a");
    klee_make_symbolic(&b, sizeof(b), "b");

    int result = min_value(a, b);

    // Property 1: Result <= both inputs
    klee_assert(result <= a);
    klee_assert(result <= b);

    // Property 2: Result equals one of the inputs
    klee_assert(result == a || result == b);

    // Property 3: Commutativity
    klee_assert(min_value(a, b) == min_value(b, a));
}

// ========== Test 7: is_even() with symbolic input ==========
void test_is_even_symbolic() {
    printf("Testing is_even() with symbolic input\n");

    int a;
    klee_make_symbolic(&a, sizeof(a), "a");

    int result = is_even(a);

    // Property 1: Result is 0 or 1 (boolean)
    klee_assert(result == 0 || result == 1);

    // Property 2: If result is 1, then a % 2 == 0
    if (result == 1) {
        klee_assert(a % 2 == 0);
    } else {
        klee_assert(a % 2 != 0);
    }

    // Property 3: Even and odd alternate
    int next = a + 1;
    int next_is_even = is_even(next);
    klee_assert(is_even(a) != next_is_even);
}

// ========== Test 8: is_positive() with symbolic input ==========
void test_is_positive_symbolic() {
    printf("Testing is_positive() with symbolic input\n");

    int a;
    klee_make_symbolic(&a, sizeof(a), "a");

    int result = is_positive(a);

    // Property 1: Result is 0 or 1
    klee_assert(result == 0 || result == 1);

    // Property 2: Result matches actual check
    if (result == 1) {
        klee_assert(a > 0);
    } else {
        klee_assert(a <= 0);
    }
}

// ========== Test 9: factorial() with symbolic input ==========
void test_factorial_symbolic() {
    printf("Testing factorial() with symbolic input\n");

    int n;
    klee_make_symbolic(&n, sizeof(n), "n");

    // Constrain to valid range (0-10 to avoid overflow)
    klee_assume(n >= -1 && n <= 10);

    int result = factorial(n);

    // Property 1: factorial(0) == 1
    if (n == 0) {
        klee_assert(result == 1);
    }

    // Property 2: factorial(1) == 1
    if (n == 1) {
        klee_assert(result == 1);
    }

    // Property 3: factorial(-1) == -1 (error case)
    if (n < 0) {
        klee_assert(result == -1);
    }

    // Property 4: factorial(n) >= 1 for n >= 0
    if (n >= 0) {
        klee_assert(result >= 1);
    }

    // Property 5: factorial(n) > n for n >= 2
    if (n >= 2) {
        klee_assert(result > n);
    }
}

// ========== Test 10: fibonacci() with symbolic input ==========
void test_fibonacci_symbolic() {
    printf("Testing fibonacci() with symbolic input\n");

    int n;
    klee_make_symbolic(&n, sizeof(n), "n");

    // Constrain to reasonable range
    klee_assume(n >= -1 && n <= 20);

    int result = fibonacci(n);

    // Property 1: fibonacci(0) == 0
    if (n == 0) {
        klee_assert(result == 0);
    }

    // Property 2: fibonacci(1) == 1
    if (n == 1) {
        klee_assert(result == 1);
    }

    // Property 3: fibonacci(-1) == -1 (error case)
    if (n < 0) {
        klee_assert(result == -1);
    }

    // Property 4: fibonacci(n) >= 0 for n >= 0
    if (n >= 0) {
        klee_assert(result >= 0);
    }

    // Property 5: fibonacci(n) >= fibonacci(n-1) for n >= 1
    if (n >= 1) {
        klee_assert(result >= fibonacci(n - 1));
    }
}

// ========== Test 11: Add commutativity (advanced) ==========
void test_add_commutativity_symbolic() {
    printf("Testing add() commutativity symbolically\n");

    int a, b;
    klee_make_symbolic(&a, sizeof(a), "a");
    klee_make_symbolic(&b, sizeof(b), "b");

    // Test: add(a, b) == add(b, a)
    klee_assert(add(a, b) == add(b, a));
}

// ========== Test 12: Multiply distributivity (advanced) ==========
void test_multiply_distributivity_symbolic() {
    printf("Testing multiply() distributivity symbolically\n");

    int a, b, c;
    klee_make_symbolic(&a, sizeof(a), "a");
    klee_make_symbolic(&b, sizeof(b), "b");
    klee_make_symbolic(&c, sizeof(c), "c");

    klee_assume(a >= -10 && a <= 10);
    klee_assume(b >= -10 && b <= 10);
    klee_assume(c >= -10 && c <= 10);

    // Test: a * (b + c) == (a * b) + (a * c)
    int left = multiply(a, add(b, c));
    int right = add(multiply(a, b), multiply(a, c));
    klee_assert(left == right);
}

// ========== Main Entry Point ==========
int main() {
    printf("========================================\n");
    printf("  KLEE Symbolic Execution Test Suite\n");
    printf("========================================\n\n");

    // Run all symbolic tests
    test_add_symbolic();
    test_subtract_symbolic();
    test_multiply_symbolic();
    test_abs_symbolic();
    test_max_symbolic();
    test_min_symbolic();
    test_is_even_symbolic();
    test_is_positive_symbolic();
    test_factorial_symbolic();
    test_fibonacci_symbolic();
    test_add_commutativity_symbolic();
    test_multiply_distributivity_symbolic();

    printf("\n========================================\n");
    printf("All symbolic tests passed!\n");
    printf("========================================\n\n");

    klee_silent_exit(0);
    return 0;
}
