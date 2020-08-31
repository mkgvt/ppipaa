#include <assert.h>
#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#include "ipanon.h"

// Helper: print externalized state for internalize tests...
#define PRINTSTATE false

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

// Print data for internalization tests...
#if PRINTSTATE
void print_state(ipanonymizer *anonymizer,
                 const unsigned char *external_state,
                 unsigned int size) {
  printf("unsigned char state[] = {\n ");
  for (unsigned int i = 0; i < crypto_generichash_KEYBYTES; ++i) {
    printf(" 0x%02X,", anonymizer->private.key[i]);
    if (((i + 1) % 8) == 0) {
      printf("\n ");
    }
  }
  for (unsigned int i = 0; i < crypto_generichash_BYTES; ++i) {
    printf(" 0x%02X,", anonymizer->private.pad[i]);
    if (((i + 1) % 8) == 0) {
      printf("\n ");
    }
  }
  printf("};\n");
  printf("unsigned char externed_state[] = {\n ");
  for (unsigned int i = 0; i < size; ++i) {
    printf(" 0x%02X,", external_state[i]);
    if (((i + 1) % 8) == 0) {
      printf("\n ");
    }
  }
  printf("\n");
}
#endif


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

  int padbytes = sizeof(anonymizer.private.pad);
  int padzeros = count_zeros(anonymizer.private.pad, padbytes);
  assert_that(padzeros, is_less_than(padbytes));
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

  int padbytes = sizeof(anonymizer.private.pad);
  int padzeros = count_zeros(anonymizer.private.pad, padbytes);
  assert_that(padzeros, is_equal_to(padbytes));
}

//-------------------------------------------------------------------------------

// Encrypted externalized state based supplied passphrase and internal state:
char *key = "passphrase";
unsigned char state[] = {
  0xE0, 0x39, 0x90, 0xB7, 0xDC, 0xC0, 0xC4, 0x78,
  0x1D, 0xF4, 0x58, 0x61, 0xC3, 0xEC, 0x67, 0x86,
  0x12, 0x17, 0x07, 0x3A, 0x3C, 0x15, 0x01, 0x94,
  0x40, 0xF9, 0xAA, 0xFD, 0x05, 0x29, 0xFD, 0x51,
  0xBE, 0xED, 0x48, 0x87, 0x2A, 0xDE, 0x6A, 0x90,
  0xB8, 0xD1, 0x26, 0x9A, 0xDC, 0x64, 0x9C, 0x1B,
  0x80, 0xC6, 0x17, 0x2A, 0xFD, 0x66, 0xAB, 0x8E,
  0x8A, 0x57, 0xC8, 0xC9, 0x30, 0x8E, 0x9F, 0xD6,
};
unsigned char externed_state[] = {
  0x4F, 0x67, 0x2D, 0x6A, 0x06, 0x9F, 0x17, 0xE2,
  0xE7, 0x20, 0x24, 0x33, 0xAC, 0xAA, 0x37, 0x79,
  0x84, 0xA3, 0x5D, 0x12, 0xC5, 0x75, 0x1E, 0xB2,
  0x22, 0x21, 0xFA, 0x63, 0x40, 0x7D, 0x5C, 0x0A,
  0x7D, 0x35, 0xAD, 0x40, 0x52, 0x0F, 0x7B, 0x83,
  0x85, 0xC0, 0x8E, 0x0E, 0x18, 0xF2, 0x86, 0x87,
  0x02, 0x34, 0x74, 0x25, 0xF2, 0x19, 0x3C, 0x41,
  0xF5, 0x64, 0xB0, 0xDE, 0xE0, 0x80, 0xB9, 0x62,
  0x20, 0xA0, 0xFE, 0xF1, 0x7C, 0x55, 0xCA, 0x69,
  0x4C, 0xB6, 0xB3, 0xA5, 0xB2, 0xB2, 0x02, 0xE3,
  0xCF, 0x54, 0x9A, 0x48, 0x5C, 0x79, 0xCA, 0xCD,
  0x37, 0xDE, 0x7D, 0x0C, 0x96, 0x0C, 0xF6, 0xFD,
  0x7C, 0xAF, 0x6C, 0x93, 0x24, 0x8C, 0x22, 0x3D,
  0xCC, 0xE1, 0xE1, 0x6B, 0x16, 0xAA, 0x35, 0x5D,
  0x60, 0x3B, 0x76, 0x1C, 0xA2, 0x51, 0x85, 0x1F,
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

  // Print data for internalization tests...
  #if PRINTSTATE
  print_state(&anonymizer, outbuf, ipanon_saved_state_size());
  #endif

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

  unsigned char *pad = ((struct private *) &state)->pad;
  int padbytes = sizeof(anonymizer.private.pad);
  int padsame = count_same(anonymizer.private.pad, pad, padbytes);
  assert_that(padsame, is_equal_to(padbytes));
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

  unsigned char *pad = ((struct private *) &state)->pad;
  int padbytes = sizeof(anonymizer.private.pad);
  int padsame = count_same(anonymizer.private.pad, pad, padbytes);
  assert_that(padsame, is_equal_to(padbytes));
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

  // Compare pads (should be different)
  int padbytes = sizeof(anonymizer1.private.pad);
  int padsame = count_same(anonymizer1.private.pad,
                           anonymizer2.private.pad, padbytes);
  assert_that(padsame, is_not_equal_to(padbytes));

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

  // Compare pads again (should be the same)
  padbytes = sizeof(anonymizer1.private.pad);
  padsame = count_same(anonymizer1.private.pad,
                       anonymizer2.private.pad, padbytes);
  assert_that(padsame, is_equal_to(padbytes));
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

  // Compare pads (should be different)
  int padbytes = sizeof(anonymizer1.private.pad);
  int padsame = count_same(anonymizer1.private.pad,
                           anonymizer2.private.pad, padbytes);
  assert_that(padsame, is_not_equal_to(padbytes));

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

  // Compare pads again (should be the same)
  padbytes = sizeof(anonymizer1.private.pad);
  padsame = count_same(anonymizer1.private.pad,
                       anonymizer2.private.pad, padbytes);
  assert_that(padsame, is_equal_to(padbytes));
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
