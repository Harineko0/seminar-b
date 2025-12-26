#include "math_utils.h"

// Add two integers
int add(int a, int b) {
    return a + b;
}

// Subtract two integers
int subtract(int a, int b) {
    return a - b;
}

// Multiply two integers
int multiply(int a, int b) {
    return a * b;
}

// Integer absolute value
int abs_value(int x) {
    if (x < 0) {
        return -x;
    }
    return x;
}

// Maximum of two integers
int max_value(int a, int b) {
    if (a > b) {
        return a;
    }
    return b;
}

// Minimum of two integers
int min_value(int a, int b) {
    if (a < b) {
        return a;
    }
    return b;
}

// Check if number is even
int is_even(int x) {
    return x % 2 == 0;
}

// Check if number is positive
int is_positive(int x) {
    return x > 0;
}

// Factorial (0 to 10)
int factorial(int n) {
    if (n < 0) {
        return -1;  // Error case
    }
    if (n == 0 || n == 1) {
        return 1;
    }

    int result = 1;
    for (int i = 2; i <= n; i++) {
        result *= i;
    }
    return result;
}

// Fibonacci number (0-indexed)
int fibonacci(int n) {
    if (n < 0) {
        return -1;  // Error case
    }
    if (n == 0) {
        return 0;
    }
    if (n == 1) {
        return 1;
    }

    int a = 0, b = 1;
    for (int i = 2; i <= n; i++) {
        int temp = a + b;
        a = b;
        b = temp;
    }
    return b;
}
