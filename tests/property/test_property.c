#include <theft.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include "math_utils.h"

// Property-Based Testing with theft Library
// Uses theft to generate random inputs and verify mathematical properties

// ============================================================
// Type Info: Generate random integers
// ============================================================

struct int_pair {
    int a;
    int b;
};

struct int_triple {
    int a;
    int b;
    int c;
};

// Allocate random integer
static enum theft_alloc_res
alloc_int(struct theft *t, void *env, void **instance) {
    int *value = malloc(sizeof(int));
    if (value == NULL) { return THEFT_ALLOC_ERROR; }

    // Generate random int in reasonable range
    *value = (int)theft_random_choice(t, 200) - 100;  // Range: -100 to 99
    *instance = value;
    return THEFT_ALLOC_OK;
}

// Allocate random integer pair
static enum theft_alloc_res
alloc_int_pair(struct theft *t, void *env, void **instance) {
    struct int_pair *pair = malloc(sizeof(struct int_pair));
    if (pair == NULL) { return THEFT_ALLOC_ERROR; }

    pair->a = (int)theft_random_choice(t, 200) - 100;
    pair->b = (int)theft_random_choice(t, 200) - 100;
    *instance = pair;
    return THEFT_ALLOC_OK;
}

// Allocate random integer triple
static enum theft_alloc_res
alloc_int_triple(struct theft *t, void *env, void **instance) {
    struct int_triple *triple = malloc(sizeof(struct int_triple));
    if (triple == NULL) { return THEFT_ALLOC_ERROR; }

    triple->a = (int)theft_random_choice(t, 100) - 50;
    triple->b = (int)theft_random_choice(t, 100) - 50;
    triple->c = (int)theft_random_choice(t, 100) - 50;
    *instance = triple;
    return THEFT_ALLOC_OK;
}

// Allocate small integer (for factorial)
static enum theft_alloc_res
alloc_small_int(struct theft *t, void *env, void **instance) {
    int *value = malloc(sizeof(int));
    if (value == NULL) { return THEFT_ALLOC_ERROR; }

    *value = (int)theft_random_choice(t, 12);  // Range: 0 to 11
    *instance = value;
    return THEFT_ALLOC_OK;
}

// Free function for all types
static void free_instance(void *instance, void *env) {
    free(instance);
}

// Type info structs
static struct theft_type_info int_info = {
    .alloc = alloc_int,
    .free = free_instance,
};

static struct theft_type_info int_pair_info = {
    .alloc = alloc_int_pair,
    .free = free_instance,
};

static struct theft_type_info int_triple_info = {
    .alloc = alloc_int_triple,
    .free = free_instance,
};

static struct theft_type_info small_int_info = {
    .alloc = alloc_small_int,
    .free = free_instance,
};

// ============================================================
// Property Tests for add()
// ============================================================

// Property: add(a, b) == add(b, a) (commutativity)
static enum theft_trial_res
prop_add_commutative(struct theft *t, void *arg1) {
    struct int_pair *pair = (struct int_pair *)arg1;
    int a = pair->a;
    int b = pair->b;

    if (add(a, b) != add(b, a)) {
        fprintf(stderr, "FAIL: add(%d, %d) != add(%d, %d)\n", a, b, b, a);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// Property: (a + b) + c == a + (b + c) (associativity)
static enum theft_trial_res
prop_add_associative(struct theft *t, void *arg1) {
    struct int_triple *triple = (struct int_triple *)arg1;
    int a = triple->a;
    int b = triple->b;
    int c = triple->c;

    if (add(add(a, b), c) != add(a, add(b, c))) {
        fprintf(stderr, "FAIL: (%d + %d) + %d != %d + (%d + %d)\n",
                a, b, c, a, b, c);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// Property: add(a, 0) == a (identity)
static enum theft_trial_res
prop_add_identity(struct theft *t, void *arg1) {
    int *value = (int *)arg1;
    int a = *value;

    if (add(a, 0) != a) {
        fprintf(stderr, "FAIL: add(%d, 0) != %d\n", a, a);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// ============================================================
// Property Tests for multiply()
// ============================================================

// Property: a * b == b * a (commutativity)
static enum theft_trial_res
prop_multiply_commutative(struct theft *t, void *arg1) {
    struct int_pair *pair = (struct int_pair *)arg1;
    int a = pair->a;
    int b = pair->b;

    if (multiply(a, b) != multiply(b, a)) {
        fprintf(stderr, "FAIL: multiply(%d, %d) != multiply(%d, %d)\n",
                a, b, b, a);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// Property: a * 1 == a (identity)
static enum theft_trial_res
prop_multiply_identity(struct theft *t, void *arg1) {
    int *value = (int *)arg1;
    int a = *value;

    if (multiply(a, 1) != a) {
        fprintf(stderr, "FAIL: multiply(%d, 1) != %d\n", a, a);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// Property: a * 0 == 0 (absorbing element)
static enum theft_trial_res
prop_multiply_zero(struct theft *t, void *arg1) {
    int *value = (int *)arg1;
    int a = *value;

    if (multiply(a, 0) != 0) {
        fprintf(stderr, "FAIL: multiply(%d, 0) != 0\n", a);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// Property: a * (b + c) == (a * b) + (a * c) (distributivity)
static enum theft_trial_res
prop_multiply_distributive(struct theft *t, void *arg1) {
    struct int_triple *triple = (struct int_triple *)arg1;
    int a = triple->a;
    int b = triple->b;
    int c = triple->c;

    int left = multiply(a, add(b, c));
    int right = add(multiply(a, b), multiply(a, c));

    if (left != right) {
        fprintf(stderr, "FAIL: %d * (%d + %d) != (%d * %d) + (%d * %d)\n",
                a, b, c, a, b, a, c);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// ============================================================
// Property Tests for abs_value()
// ============================================================

// Property: abs(a) >= 0 (non-negative)
static enum theft_trial_res
prop_abs_nonnegative(struct theft *t, void *arg1) {
    int *value = (int *)arg1;
    int a = *value;

    if (abs_value(a) < 0) {
        fprintf(stderr, "FAIL: abs_value(%d) < 0\n", a);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// Property: abs(-a) == abs(a) (symmetry)
static enum theft_trial_res
prop_abs_symmetric(struct theft *t, void *arg1) {
    int *value = (int *)arg1;
    int a = *value;

    if (abs_value(a) != abs_value(-a)) {
        fprintf(stderr, "FAIL: abs_value(%d) != abs_value(%d)\n", a, -a);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// ============================================================
// Property Tests for max_value() and min_value()
// ============================================================

// Property: max(a, b) >= a && max(a, b) >= b
static enum theft_trial_res
prop_max_bounds(struct theft *t, void *arg1) {
    struct int_pair *pair = (struct int_pair *)arg1;
    int a = pair->a;
    int b = pair->b;
    int result = max_value(a, b);

    if (result < a || result < b) {
        fprintf(stderr, "FAIL: max_value(%d, %d) = %d is not >= both\n",
                a, b, result);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// Property: max(a, b) == max(b, a) (commutativity)
static enum theft_trial_res
prop_max_commutative(struct theft *t, void *arg1) {
    struct int_pair *pair = (struct int_pair *)arg1;
    int a = pair->a;
    int b = pair->b;

    if (max_value(a, b) != max_value(b, a)) {
        fprintf(stderr, "FAIL: max_value(%d, %d) != max_value(%d, %d)\n",
                a, b, b, a);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// Property: min(a, b) <= a && min(a, b) <= b
static enum theft_trial_res
prop_min_bounds(struct theft *t, void *arg1) {
    struct int_pair *pair = (struct int_pair *)arg1;
    int a = pair->a;
    int b = pair->b;
    int result = min_value(a, b);

    if (result > a || result > b) {
        fprintf(stderr, "FAIL: min_value(%d, %d) = %d is not <= both\n",
                a, b, result);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// ============================================================
// Property Tests for factorial()
// ============================================================

// Property: factorial(n) >= 1 for n >= 0
static enum theft_trial_res
prop_factorial_positive(struct theft *t, void *arg1) {
    int *value = (int *)arg1;
    int n = *value;

    if (n < 0) { return THEFT_TRIAL_SKIP; }

    int result = factorial(n);
    if (result < 1) {
        fprintf(stderr, "FAIL: factorial(%d) = %d < 1\n", n, result);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// Property: factorial(n) = n * factorial(n-1)
static enum theft_trial_res
prop_factorial_recursive(struct theft *t, void *arg1) {
    int *value = (int *)arg1;
    int n = *value;

    if (n < 2) { return THEFT_TRIAL_SKIP; }

    int result1 = factorial(n);
    int result2 = multiply(n, factorial(n - 1));

    if (result1 != result2) {
        fprintf(stderr, "FAIL: factorial(%d) != %d * factorial(%d)\n",
                n, n, n - 1);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// ============================================================
// Property Tests for fibonacci()
// ============================================================

// Property: fibonacci(n) >= 0 for n >= 0
static enum theft_trial_res
prop_fibonacci_nonnegative(struct theft *t, void *arg1) {
    int *value = (int *)arg1;
    int n = *value;

    if (n < 0) { return THEFT_TRIAL_SKIP; }

    int result = fibonacci(n);
    if (result < 0) {
        fprintf(stderr, "FAIL: fibonacci(%d) = %d < 0\n", n, result);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// Property: fibonacci(n) = fibonacci(n-1) + fibonacci(n-2)
static enum theft_trial_res
prop_fibonacci_recursive(struct theft *t, void *arg1) {
    int *value = (int *)arg1;
    int n = *value;

    if (n < 2) { return THEFT_TRIAL_SKIP; }

    int result1 = fibonacci(n);
    int result2 = add(fibonacci(n - 1), fibonacci(n - 2));

    if (result1 != result2) {
        fprintf(stderr, "FAIL: fibonacci(%d) != fibonacci(%d) + fibonacci(%d)\n",
                n, n - 1, n - 2);
        return THEFT_TRIAL_FAIL;
    }
    return THEFT_TRIAL_PASS;
}

// ============================================================
// Test Runner
// ============================================================

typedef struct {
    const char *name;
    enum theft_trial_res (*prop)(struct theft *, void *);
    struct theft_type_info *type_info;
    int trials;
} test_case;

int main(void) {
    printf("========================================\n");
    printf("  Property-Based Testing with theft\n");
    printf("========================================\n\n");

    // Define test cases
    test_case tests[] = {
        // add() properties
        {"add_commutative", prop_add_commutative, &int_pair_info, 1000},
        {"add_associative", prop_add_associative, &int_triple_info, 1000},
        {"add_identity", prop_add_identity, &int_info, 1000},

        // multiply() properties
        {"multiply_commutative", prop_multiply_commutative, &int_pair_info, 1000},
        {"multiply_identity", prop_multiply_identity, &int_info, 1000},
        {"multiply_zero", prop_multiply_zero, &int_info, 1000},
        {"multiply_distributive", prop_multiply_distributive, &int_triple_info, 1000},

        // abs_value() properties
        {"abs_nonnegative", prop_abs_nonnegative, &int_info, 1000},
        {"abs_symmetric", prop_abs_symmetric, &int_info, 1000},

        // max/min properties
        {"max_bounds", prop_max_bounds, &int_pair_info, 1000},
        {"max_commutative", prop_max_commutative, &int_pair_info, 1000},
        {"min_bounds", prop_min_bounds, &int_pair_info, 1000},

        // factorial() properties
        {"factorial_positive", prop_factorial_positive, &small_int_info, 100},
        {"factorial_recursive", prop_factorial_recursive, &small_int_info, 100},

        // fibonacci() properties
        {"fibonacci_nonnegative", prop_fibonacci_nonnegative, &small_int_info, 100},
        {"fibonacci_recursive", prop_fibonacci_recursive, &small_int_info, 100},
    };

    int total_tests = sizeof(tests) / sizeof(tests[0]);
    int passed = 0;
    int failed = 0;

    // Run each test
    for (int i = 0; i < total_tests; i++) {
        test_case *tc = &tests[i];

        struct theft_run_config config = {
            .name = tc->name,
            .prop1 = tc->prop,
            .type_info = { tc->type_info },
            .trials = tc->trials,
            .seed = 0,  // Use deterministic seed for reproducibility
        };

        printf("Running property: %s (%d trials)...\n", tc->name, tc->trials);

        enum theft_run_res res = theft_run(&config);

        if (res == THEFT_RUN_PASS) {
            printf("  ✓ PASS\n\n");
            passed++;
        } else {
            printf("  ✗ FAIL (result code: %d)\n\n", res);
            failed++;
        }
    }

    // Summary
    printf("========================================\n");
    printf("Test Results Summary\n");
    printf("========================================\n");
    printf("Total Tests:  %d\n", total_tests);
    printf("Passed:       %d\n", passed);
    printf("Failed:       %d\n", failed);
    printf("Pass Rate:    %.1f%%\n",
           (total_tests > 0) ? (100.0 * passed / total_tests) : 0.0);
    printf("========================================\n");

    return (failed == 0) ? 0 : 1;
}
