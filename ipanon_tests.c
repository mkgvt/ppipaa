#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>


#include "ipanon.h"

Describe(ipanon_tests);
BeforeEach(ipanon_tests) {}
AfterEach(ipanon_tests) {}

//-------------------------------------------------------------------------------

Ensure(ipanon_tests, init_returns_error_on_null) {
  ipanon_errno err = ipanon_init(NULL);
  assert_that(err, is_equal_to(IPANON_ERROR_NULL));
}

Ensure(ipanon_tests, init_returns_ok_with_stack_allocation) {
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert_that(err, is_equal_to(IPANON_OK));
}

Ensure(ipanon_tests, init_returns_ok_with_heap_allocation) {
  ipanonymizer *anonymizer = malloc(sizeof(ipanonymizer));
  assert_that(anonymizer, is_not_null);
  ipanon_errno err = ipanon_init(anonymizer);
  assert_that(err, is_equal_to(IPANON_OK));
  free(anonymizer);
}

Ensure(ipanon_tests, init_initializes_key) {
  // Strategy: Set key to all zeros. The key should not be all zeros anymore
  // after calling init. (Requires accessing private internals directly.)
  //
  // Note: there is an extremely low (but non-zero) probability that the key
  // is still all zeros after initialization since that can occur by
  // definition. Thus this check may fail but it is highly unlikely.
  ipanonymizer anonymizer;
  memset(anonymizer._key, 0, sizeof(anonymizer._key));
  ipanon_init(&anonymizer);
  int bytes = sizeof(anonymizer._key);
  int zeros = 0;
  for (int i = 0; i < bytes; ++i) {
    if (anonymizer._key[i] == 0) {
      ++zeros;
    }
  }
  assert_that(zeros, is_less_than(bytes));
}

//-------------------------------------------------------------------------------

Ensure(ipanon_tests, deinit_returns_error_on_null) {
  ipanonymizer anonymizer;
  ipanon_init(&anonymizer);
  ipanon_errno err = anonymizer.deinit(NULL);
  assert_that(err, is_equal_to(IPANON_ERROR_NULL));
}

Ensure(ipanon_tests, deinit_returns_ok_on_nonnull) {
  ipanonymizer anonymizer;
  ipanon_init(&anonymizer);
  ipanon_errno err = anonymizer.deinit(&anonymizer);
  assert_that(err, is_equal_to(IPANON_OK));
}

Ensure(ipanon_tests, deinit_zeros_key) {
  ipanonymizer anonymizer;
  ipanon_init(&anonymizer);
  anonymizer.deinit(&anonymizer);
  int bytes = sizeof(anonymizer._key);
  int zeros = 0;
  for (int i = 0; i < bytes; ++i) {
    if (anonymizer._key[i] == 0) {
      ++zeros;
    }
  }
  assert_that(zeros, is_equal_to(bytes));
}

//-------------------------------------------------------------------------------

TestSuite *ipanon_tests() {
    TestSuite *suite = create_test_suite();

    add_test_with_context(suite, ipanon_tests, init_returns_error_on_null);
    add_test_with_context(suite, ipanon_tests, init_returns_ok_with_stack_allocation);
    add_test_with_context(suite, ipanon_tests, init_returns_ok_with_heap_allocation);
    add_test_with_context(suite, ipanon_tests, init_initializes_key);

    add_test_with_context(suite, ipanon_tests, deinit_returns_error_on_null);
    add_test_with_context(suite, ipanon_tests, deinit_returns_ok_on_nonnull);

    return suite;
}
