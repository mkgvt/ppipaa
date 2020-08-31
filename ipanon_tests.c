#include <assert.h>
#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#include "ipanon.h"

Describe(ipanon_tests);
BeforeEach(ipanon_tests) {}
AfterEach(ipanon_tests) {}

//-------------------------------------------------------------------------------
// Helper functions factoring out common testing patterns

static int last_nonzero(unsigned char *data, int bytes) {
  int end;
  for (end = bytes - 1; end > 0; --end) {
    if (data[end] != 0) {
      break;
    }
  }
  return end;
}


static int count_zeros(unsigned char *data, int bytes) {
  int zeros = 0;
  for (int i = 0; i < bytes; ++i) {
    if (data[i] == 0) {
      ++zeros;
    }
  }
  return zeros;
}


static int count_same(unsigned char *data1, unsigned char *data2, int bytes) {
  int same = 0;
  for (int i = 0; i < bytes; ++i) {
    if (data1[i] == data2[i]) {
      ++same;
    }
  }
  return same;
}


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
  assert(anonymizer != NULL);
  ipanon_errno err = ipanon_init(anonymizer);
  assert_that(err, is_equal_to(IPANON_OK));
  free(anonymizer);
}


Ensure(ipanon_tests, init_initializes_private) {
  // Strategy: set state to zero. State should not be zero after init.
  // (Requires accessing private internals directly.)
  //
  // Note: there is an extremely low (but non-zero) probability that the state
  // is still all zeros after initialization since that can occur by
  // randomization. Thus this check may fail but it is highly unlikely.
  ipanonymizer anonymizer;
  memset(&anonymizer.private, 0, sizeof(anonymizer.private));
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  int keybytes = sizeof(anonymizer.private.key);
  int keyzeros = count_zeros(anonymizer.private.key, keybytes);
  assert_that(keyzeros, is_less_than(keybytes));
}

//-------------------------------------------------------------------------------

Ensure(ipanon_tests, deinit_returns_error_on_null) {
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  err = anonymizer.deinit(NULL);
  assert_that(err, is_equal_to(IPANON_ERROR_NULL));
}


Ensure(ipanon_tests, deinit_returns_ok_on_nonnull) {
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  err = anonymizer.deinit(&anonymizer);
  assert_that(err, is_equal_to(IPANON_OK));
}


Ensure(ipanon_tests, deinit_zeros_state) {
  // Strategy: the state should be all zeros after after deinit.
  // (Requires accessing private internals directly.)
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  err = anonymizer.deinit(&anonymizer);
  assert(err == IPANON_OK);

  int keybytes = sizeof(anonymizer.private.key);
  int keyzeros = count_zeros(anonymizer.private.key, keybytes);
  assert_that(keyzeros, is_equal_to(keybytes));
}

//-------------------------------------------------------------------------------

// Encrypted externalized state based supplied passphrase and internal state:
// - passphrase: "passphrase"
// - state: 0x1757D1BCFCA3048BF5EF6BC695826BD7A67F8DE193D8878A5C6A174322C44D86
// - salt: 0x40851C45719A77F70C97D03B8BCC5514
// - nonce: 0xE3EC3EA5F509571B703C8DD97A677CB48BDE88DB0956FFCE
char *key = "passphrase";
unsigned char state[] = {
  0x17, 0x57, 0xD1, 0xBC, 0xFC, 0xA3, 0x04, 0x8B,
  0xF5, 0xEF, 0x6B, 0xC6, 0x95, 0x82, 0x6B, 0xD7,
  0xA6, 0x7F, 0x8D, 0xE1, 0x93, 0xD8, 0x87, 0x8A,
  0x5C, 0x6A, 0x17, 0x43, 0x22, 0xC4, 0x4D, 0x86,
};
unsigned char externed_state[] = {
  0x40, 0x85, 0x1C, 0x45, 0x71, 0x9A, 0x77, 0xF7,
  0x0C, 0x97, 0xD0, 0x3B, 0x8B, 0xCC, 0x55, 0x14,
  0xE3, 0xEC, 0x3E, 0xA5, 0xF5, 0x09, 0x57, 0x1B,
  0x70, 0x3C, 0x8D, 0xD9, 0x7A, 0x67, 0x7C, 0xB4,
  0x8B, 0xDE, 0x88, 0xDB, 0x09, 0x56, 0xFF, 0xCE,
  0x54, 0xA2, 0x7D, 0x98, 0xBD, 0x1E, 0xFE, 0xBE,
  0x96, 0xB5, 0x84, 0xFB, 0x63, 0xA2, 0xCA, 0xFE,
  0xEC, 0x58, 0x46, 0x45, 0xA4, 0x02, 0xA0, 0x18,
  0x33, 0xDE, 0x4E, 0xC9, 0xBE, 0xC1, 0x20, 0xC7,
  0x30, 0x97, 0x2D, 0x59, 0x1B, 0xD8, 0xEC, 0x5B,
  0x36, 0xB5, 0x42, 0x38, 0xD1, 0x1A, 0x8A, 0x84,
};


Ensure(ipanon_tests, externalize_returns_error_on_null) {
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  char *key = "unused";
  unsigned char outbuf[1]; // should be unused
  FILE *out = fmemopen(outbuf, sizeof(outbuf), "w");
  err = anonymizer.externalize(NULL, out, key, strlen(key));
  assert_that(err, is_equal_to(IPANON_ERROR_NULL));
  fclose(out);
}


Ensure(ipanon_tests, externalize_saves_plaintext_state) {
  // Strategy: fill buffer with zeros, externalize to buffer, and check
  // backwards from end of buffer for first non-zero byte. There should be a
  // non-zero byte in the buffer.
  //
  // Note: there is an extremely low (but non-zero) probability that the state
  // was all zeros. Thus this check may fail but it is highly unlikely.
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  // Note: fmemopen writes \0 to last spot, make room...
  unsigned char outbuf[ipanon_saved_state_size() + 1];
  memset(outbuf, 0, sizeof(outbuf));

  FILE *out = fmemopen(outbuf, sizeof(outbuf), "w");
  err = anonymizer.externalize(&anonymizer, out, NULL, 0);
  assert_that(err, is_equal_to(IPANON_OK));
  fclose(out);

  // Work backwards until the first non-zero byte
  int end = last_nonzero(outbuf, sizeof(outbuf));
  assert_that(end, is_greater_than(0));
}


Ensure(ipanon_tests, externalize_saves_encrypted_state) {
  // Strategy: fill buffer with zeros, externalize to buffer, and check
  // backwards from end of buffer for first non-zero byte. There should be a
  // non-zero byte in the buffer.
  //
  // Note: there is an extremely low (but non-zero) probability that the state
  // was all zeros. Thus this check may fail but it is highly unlikely.
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  // Note: fmemopen writes \0 to last spot, make room...
  unsigned char outbuf[ipanon_saved_state_size() + 1];
  memset(outbuf, 0, sizeof(outbuf));

  FILE *out = fmemopen(outbuf, sizeof(outbuf), "w");
  err = anonymizer.externalize(&anonymizer, out, key, strlen(key));
  assert_that(err, is_equal_to(IPANON_OK));
  fclose(out);

  // Work backwards until the first non-zero byte
  int end = last_nonzero(outbuf, sizeof(outbuf));
  assert_that(end, is_greater_than(0));
}


Ensure(ipanon_tests, internalize_returns_error_on_null) {
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  unsigned char inbuf[] = "state";
  FILE *unused = fmemopen(inbuf, sizeof(inbuf), "r");
  err = anonymizer.internalize(NULL, unused, key, strlen(key));
  fclose(unused);
  assert_that(err, is_equal_to(IPANON_ERROR_NULL));
}


Ensure(ipanon_tests, internalize_restores_plaintext_state) {
  // Strategy: set state to all zeros. Internalize state. The internalized
  // state should exactly match the expected internal state.
  // (Requires accessing private internals directly.)
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);
  memset(&anonymizer.private, 0, sizeof(anonymizer.private));

  FILE *in = fmemopen(state, sizeof(state), "r");
  err = anonymizer.internalize(&anonymizer, in, NULL, 0);
  assert_that(err, is_equal_to(IPANON_OK));
  fclose(in);

  unsigned char *key = ((struct private *) &state)->key;
  int keybytes = sizeof(anonymizer.private.key);
  int keysame = count_same(anonymizer.private.key, key, keybytes);
  assert_that(keysame, is_equal_to(keybytes));
}


Ensure(ipanon_tests, internalize_restores_encrypted_state) {
  // Strategy: set state to all zeros. Internalize state. The internalized
  // state should exactly match the expected internal state.
  // (Requires accessing private internals directly.)
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);
  memset(&anonymizer.private, 0, sizeof(anonymizer.private));

  FILE *in = fmemopen(externed_state, sizeof(externed_state), "r");
  err = anonymizer.internalize(&anonymizer, in, key, strlen(key));
  assert_that(err, is_equal_to(IPANON_OK));
  fclose(in);

  unsigned char *key = ((struct private *) &state)->key;
  int keybytes = sizeof(anonymizer.private.key);
  int keysame = count_same(anonymizer.private.key, key, keybytes);
  assert_that(keysame, is_equal_to(keybytes));
}


Ensure(ipanon_tests, internalize_restores_encrypted_state_bad_pass) {
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  char *key = "badpass";
  FILE *in = fmemopen(externed_state, sizeof(externed_state), "r");
  err = anonymizer.internalize(&anonymizer, in, key, strlen(key));
  assert_that(err, is_equal_to(IPANON_ERROR_INTERN));
  fclose(in);
}


Ensure(ipanon_tests, externalize_internalize_roundtrip_plaintext) {
  // Strategy: create two anonymizers and compare their state which should be
  // different. Externalize first anonymizer and internalize into second. The
  // two states should be identical. (Requires accessing private internals
  // directly.)
  ipanonymizer anonymizer1, anonymizer2;
  ipanon_errno err = ipanon_init(&anonymizer1);
  assert(err == IPANON_OK);
  err = ipanon_init(&anonymizer2);
  assert(err == IPANON_OK);

  // Compare keys (should be different)
  int keybytes = sizeof(anonymizer1.private.key);
  int keysame = count_same(anonymizer1.private.key,
                           anonymizer2.private.key, keybytes);
  assert_that(keysame, is_not_equal_to(keybytes));

  // Externalize
  // Note: fmemopen writes \0 to last spot, make room...
  unsigned char buf[ipanon_saved_state_size() + 1];
  FILE *out = fmemopen(buf, sizeof(buf), "w");
  err = anonymizer1.externalize(&anonymizer1, out, NULL, 0);
  assert(err == IPANON_OK);
  fclose(out);

  // Internalize
  FILE *in = fmemopen(buf, sizeof(buf), "r");
  err = anonymizer2.internalize(&anonymizer2, in, NULL, 0);
  assert(err == IPANON_OK);
  fclose(in);

  // Compare keys again (should be the same)
  keybytes = sizeof(anonymizer1.private.key);
  keysame = count_same(anonymizer1.private.key,
                           anonymizer2.private.key, keybytes);
  assert_that(keysame, is_equal_to(keybytes));
}


Ensure(ipanon_tests, externalize_internalize_roundtrip_encrypted) {
  // Strategy: create two anonymizers and compare their keys which should be
  // different. Externalize first anonymizer and internalize into second. The
  // two keys should be identical. (Requires accessing private internals
  // directly.)
  ipanonymizer anonymizer1, anonymizer2;
  ipanon_errno err = ipanon_init(&anonymizer1);
  assert(err == IPANON_OK);
  err = ipanon_init(&anonymizer2);
  assert(err == IPANON_OK);

  // Compare keys (should be different)
  int keybytes = sizeof(anonymizer1.private.key);
  int keysame = count_same(anonymizer1.private.key,
                           anonymizer2.private.key, keybytes);
  assert_that(keysame, is_not_equal_to(keybytes));

  // Externalize
  // Note: fmemopen writes \0 to last spot, make room...
  unsigned char buf[ipanon_saved_state_size() + 1];
  FILE *out = fmemopen(buf, sizeof(buf), "w");
  err = anonymizer1.externalize(&anonymizer1, out, key, strlen(key));
  assert(err == IPANON_OK);
  fclose(out);

  // Internalize
  FILE *in = fmemopen(buf, sizeof(buf), "r");
  err = anonymizer2.internalize(&anonymizer2, in, key, strlen(key));
  assert(err == IPANON_OK);
  fclose(in);

  // Compare keys again (should be the same)
  keybytes = sizeof(anonymizer1.private.key);
  keysame = count_same(anonymizer1.private.key,
                           anonymizer2.private.key, keybytes);
  assert_that(keysame, is_equal_to(keybytes));
}

//-------------------------------------------------------------------------------

TestSuite *ipanon_tests() {
    TestSuite *suite = create_test_suite();

    add_test_with_context(suite, ipanon_tests, init_returns_error_on_null);
    add_test_with_context(suite, ipanon_tests, init_returns_ok_with_stack_allocation);
    add_test_with_context(suite, ipanon_tests, init_returns_ok_with_heap_allocation);
    add_test_with_context(suite, ipanon_tests, init_initializes_private);

    add_test_with_context(suite, ipanon_tests, deinit_returns_error_on_null);
    add_test_with_context(suite, ipanon_tests, deinit_returns_ok_on_nonnull);
    add_test_with_context(suite, ipanon_tests, deinit_zeros_state);

    add_test_with_context(suite, ipanon_tests, externalize_returns_error_on_null);
    add_test_with_context(suite, ipanon_tests, externalize_saves_plaintext_state);
    add_test_with_context(suite, ipanon_tests, externalize_saves_encrypted_state);
    add_test_with_context(suite, ipanon_tests, internalize_returns_error_on_null);
    add_test_with_context(suite, ipanon_tests, internalize_restores_plaintext_state);
    add_test_with_context(suite, ipanon_tests, internalize_restores_encrypted_state);
    add_test_with_context(suite, ipanon_tests, internalize_restores_encrypted_state_bad_pass);
    add_test_with_context(suite, ipanon_tests, externalize_internalize_roundtrip_plaintext);
    add_test_with_context(suite, ipanon_tests, externalize_internalize_roundtrip_encrypted);

    return suite;
}
