#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "math_utils.h"

// Mutation Testing Test Suite
// These tests are designed to catch common mutations

int test_count = 0;
int pass_count = 0;
int fail_count = 0;

#define TEST(name, condition) \
    do { \
        test_count++; \
        if (condition) { \
            pass_count++; \
            printf("✓ %s\n", name); \
        } else { \
            fail_count++; \
            printf("✗ %s\n", name); \
        } \
    } while (0)

// ============ ADD Tests ============
void test_add() {
    printf("\n--- Testing add() ---\n");

    // Basic addition
    TEST("add(2, 3) == 5", add(2, 3) == 5);
    TEST("add(0, 5) == 5", add(0, 5) == 5);
    TEST("add(5, 0) == 5", add(5, 0) == 5);

    // Commutative property: a + b == b + a
    TEST("add(3, 7) == add(7, 3)", add(3, 7) == add(7, 3));

    // Negative numbers
    TEST("add(-2, 3) == 1", add(-2, 3) == 1);
    TEST("add(2, -3) == -1", add(2, -3) == -1);
    TEST("add(-2, -3) == -5", add(-2, -3) == -5);

    // Large numbers
    TEST("add(1000, 2000) == 3000", add(1000, 2000) == 3000);

    // Identity: a + 0 == a
    TEST("add(42, 0) == 42", add(42, 0) == 42);
}

// ============ SUBTRACT Tests ============
void test_subtract() {
    printf("\n--- Testing subtract() ---\n");

    // Basic subtraction
    TEST("subtract(5, 3) == 2", subtract(5, 3) == 2);
    TEST("subtract(10, 0) == 10", subtract(10, 0) == 10);
    TEST("subtract(5, 5) == 0", subtract(5, 5) == 0);

    // Negative results
    TEST("subtract(3, 5) == -2", subtract(3, 5) == -2);

    // With negative numbers
    TEST("subtract(-2, 3) == -5", subtract(-2, 3) == -5);
    TEST("subtract(2, -3) == 5", subtract(2, -3) == 5);

    // Anti-commutative: a - b != b - a (unless equal)
    TEST("subtract(7, 3) != subtract(3, 7)", subtract(7, 3) != subtract(3, 7));

    // Identity: a - 0 == a
    TEST("subtract(42, 0) == 42", subtract(42, 0) == 42);
}

// ============ MULTIPLY Tests ============
void test_multiply() {
    printf("\n--- Testing multiply() ---\n");

    // Basic multiplication
    TEST("multiply(3, 4) == 12", multiply(3, 4) == 12);
    TEST("multiply(5, 2) == 10", multiply(5, 2) == 10);

    // Commutative: a * b == b * a
    TEST("multiply(3, 7) == multiply(7, 3)", multiply(3, 7) == multiply(7, 3));

    // Multiplicative identity: a * 1 == a
    TEST("multiply(42, 1) == 42", multiply(42, 1) == 42);
    TEST("multiply(1, 42) == 42", multiply(1, 42) == 42);

    // Multiplicative zero: a * 0 == 0
    TEST("multiply(42, 0) == 0", multiply(42, 0) == 0);
    TEST("multiply(0, 42) == 0", multiply(0, 42) == 0);

    // Negative multiplication
    TEST("multiply(-3, 4) == -12", multiply(-3, 4) == -12);
    TEST("multiply(-3, -4) == 12", multiply(-3, -4) == 12);
}

// ============ ABS_VALUE Tests ============
void test_abs_value() {
    printf("\n--- Testing abs_value() ---\n");

    // Positive numbers
    TEST("abs_value(5) == 5", abs_value(5) == 5);
    TEST("abs_value(100) == 100", abs_value(100) == 100);

    // Negative numbers
    TEST("abs_value(-5) == 5", abs_value(-5) == 5);
    TEST("abs_value(-100) == 100", abs_value(-100) == 100);

    // Zero
    TEST("abs_value(0) == 0", abs_value(0) == 0);

    // Result is always non-negative
    TEST("abs_value(42) >= 0", abs_value(42) >= 0);
    TEST("abs_value(-42) >= 0", abs_value(-42) >= 0);
}

// ============ MAX_VALUE Tests ============
void test_max_value() {
    printf("\n--- Testing max_value() ---\n");

    TEST("max_value(5, 3) == 5", max_value(5, 3) == 5);
    TEST("max_value(3, 5) == 5", max_value(3, 5) == 5);
    TEST("max_value(5, 5) == 5", max_value(5, 5) == 5);

    // Negative numbers
    TEST("max_value(-2, -5) == -2", max_value(-2, -5) == -2);
    TEST("max_value(-5, 3) == 3", max_value(-5, 3) == 3);

    // Result is >= both inputs
    TEST("max_value(10, 20) >= 10", max_value(10, 20) >= 10);
    TEST("max_value(10, 20) >= 20", max_value(10, 20) >= 20);
}

// ============ MIN_VALUE Tests ============
void test_min_value() {
    printf("\n--- Testing min_value() ---\n");

    TEST("min_value(5, 3) == 3", min_value(5, 3) == 3);
    TEST("min_value(3, 5) == 3", min_value(3, 5) == 3);
    TEST("min_value(5, 5) == 5", min_value(5, 5) == 5);

    // Negative numbers
    TEST("min_value(-2, -5) == -5", min_value(-2, -5) == -5);
    TEST("min_value(-5, 3) == -5", min_value(-5, 3) == -5);

    // Result is <= both inputs
    TEST("min_value(10, 20) <= 10", min_value(10, 20) <= 10);
    TEST("min_value(10, 20) <= 20", min_value(10, 20) <= 20);
}

// ============ IS_EVEN Tests ============
void test_is_even() {
    printf("\n--- Testing is_even() ---\n");

    // Even numbers
    TEST("is_even(0) == 1", is_even(0) == 1);
    TEST("is_even(2) == 1", is_even(2) == 1);
    TEST("is_even(100) == 1", is_even(100) == 1);

    // Odd numbers
    TEST("is_even(1) == 0", is_even(1) == 0);
    TEST("is_even(3) == 0", is_even(3) == 0);
    TEST("is_even(99) == 0", is_even(99) == 0);

    // Negative even
    TEST("is_even(-2) == 1", is_even(-2) == 1);
    TEST("is_even(-1) == 0", is_even(-1) == 0);
}

// ============ IS_POSITIVE Tests ============
void test_is_positive() {
    printf("\n--- Testing is_positive() ---\n");

    // Positive numbers
    TEST("is_positive(1) == 1", is_positive(1) == 1);
    TEST("is_positive(100) == 1", is_positive(100) == 1);

    // Zero and negative
    TEST("is_positive(0) == 0", is_positive(0) == 0);
    TEST("is_positive(-1) == 0", is_positive(-1) == 0);
    TEST("is_positive(-100) == 0", is_positive(-100) == 0);
}

// ============ FACTORIAL Tests ============
void test_factorial() {
    printf("\n--- Testing factorial() ---\n");

    TEST("factorial(0) == 1", factorial(0) == 1);
    TEST("factorial(1) == 1", factorial(1) == 1);
    TEST("factorial(2) == 2", factorial(2) == 2);
    TEST("factorial(3) == 6", factorial(3) == 6);
    TEST("factorial(4) == 24", factorial(4) == 24);
    TEST("factorial(5) == 120", factorial(5) == 120);
    TEST("factorial(10) == 3628800", factorial(10) == 3628800);

    // Error case
    TEST("factorial(-1) == -1", factorial(-1) == -1);
}

// ============ FIBONACCI Tests ============
void test_fibonacci() {
    printf("\n--- Testing fibonacci() ---\n");

    TEST("fibonacci(0) == 0", fibonacci(0) == 0);
    TEST("fibonacci(1) == 1", fibonacci(1) == 1);
    TEST("fibonacci(2) == 1", fibonacci(2) == 1);
    TEST("fibonacci(3) == 2", fibonacci(3) == 2);
    TEST("fibonacci(4) == 3", fibonacci(4) == 3);
    TEST("fibonacci(5) == 5", fibonacci(5) == 5);
    TEST("fibonacci(6) == 8", fibonacci(6) == 8);
    TEST("fibonacci(7) == 13", fibonacci(7) == 13);
    TEST("fibonacci(8) == 21", fibonacci(8) == 21);
    TEST("fibonacci(9) == 34", fibonacci(9) == 34);
    TEST("fibonacci(10) == 55", fibonacci(10) == 55);

    // Error case
    TEST("fibonacci(-1) == -1", fibonacci(-1) == -1);

    // Fibonacci property: fib(n) = fib(n-1) + fib(n-2)
    TEST("fibonacci(5) == fibonacci(4) + fibonacci(3)",
         fibonacci(5) == fibonacci(4) + fibonacci(3));
}

int main() {
    printf("========================================\n");
    printf("  Mutation Testing Test Suite\n");
    printf("========================================\n");

    test_add();
    test_subtract();
    test_multiply();
    test_abs_value();
    test_max_value();
    test_min_value();
    test_is_even();
    test_is_positive();
    test_factorial();
    test_fibonacci();

    // Summary
    printf("\n========================================\n");
    printf("Test Results Summary\n");
    printf("========================================\n");
    printf("Total Tests:  %d\n", test_count);
    printf("Passed:       %d\n", pass_count);
    printf("Failed:       %d\n", fail_count);
    printf("Pass Rate:    %.1f%%\n", (test_count > 0) ? (100.0 * pass_count / test_count) : 0.0);
    printf("========================================\n");

    return (fail_count == 0) ? 0 : 1;
}
