#include <arpa/inet.h>
#include <assert.h>
#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#include "ipanon.h"
#include "uint128.h"

//-------------------------------------------------------------------------------

Describe(ipanon_tests);
BeforeEach(ipanon_tests) {}
AfterEach(ipanon_tests) {}

//-------------------------------------------------------------------------------

// IP addresses for testing
const char *ipv4addr = "198.51.100.47";
const char *ipv6addr = "2001:DB8:4e38::E480:F6D7:c785:49e8";

// Test passphrase
char *key = "passphrase";

// Set to true to print the internal and external state for tests
#define PRINTSTATE false

// Internal state (key and pad)
//
// There is a non-zero probability that a correctly anonymized address will
// be the same as the unanonynized address, especially for larger prefix
// sizes. The issue is that there is a 1/2^suffix chance that the anonymized
// address has the same suffix as the unanonymized address. Hence there is a
// high probability of test failure for prefixes approaching the full length
// of the IP address.
//
// By trial and error, values for key and pad were found which succeed. A
// change in the anonymizataion function will likely require new constants.
// Set PRINTSTATE (above) to true and run intil you find a good state where
// all the IPv4 and IPv6 anonymization checks all succeed, assuming that you
// trust the implementation...
unsigned char state[] = {
  0x2B, 0x91, 0xD1, 0xDF, 0xAE, 0x39, 0x8C, 0xBC,
  0xF8, 0xCA, 0x1E, 0xFF, 0x81, 0x9F, 0x75, 0x6B,
  0x87, 0xD1, 0x02, 0xF6, 0x5E, 0x54, 0x43, 0x65,
  0x7B, 0xED, 0xFC, 0x60, 0xF7, 0x30, 0xB8, 0xB9,
  0xCC, 0xF7, 0x86, 0x7D, 0x63, 0xBD, 0x2F, 0x11,
  0x4D, 0xC5, 0x39, 0x3C, 0xAA, 0x88, 0x2B, 0xCF,
  0xD9, 0x8D, 0x04, 0xC1, 0x4E, 0x8D, 0x0C, 0x71,
  0x5A, 0xF2, 0x18, 0xED, 0x03, 0xB8, 0xC8, 0x13,
 };

// Encrypted externalized state (depends on passphrase and internal state)
unsigned char externed_state[] = {
  0x4D, 0xB1, 0xFD, 0x9E, 0x40, 0xE0, 0xC9, 0x2A,
  0x63, 0x8B, 0xB1, 0x53, 0x54, 0x67, 0x47, 0x88,
  0xB7, 0xFE, 0x19, 0x07, 0xFE, 0xC3, 0x1B, 0xBB,
  0x61, 0xD8, 0x19, 0x07, 0x74, 0x1D, 0x6C, 0xA0,
  0x27, 0x69, 0x18, 0x32, 0x4C, 0x06, 0x7C, 0xBE,
  0xDC, 0xCE, 0x17, 0xCC, 0x05, 0x42, 0x28, 0xC7,
  0x2F, 0xA2, 0x66, 0xCB, 0xDE, 0x87, 0x1D, 0x81,
  0xF8, 0x01, 0xAB, 0xA7, 0x3F, 0xFD, 0x69, 0xAA,
  0xD3, 0x98, 0x72, 0x8E, 0x55, 0xE2, 0x95, 0x4A,
  0xFC, 0x1B, 0xAD, 0x8E, 0x3C, 0x64, 0xD2, 0xBF,
  0xBD, 0x93, 0xF0, 0x60, 0xAE, 0xD0, 0x93, 0xA7,
  0x7E, 0x0E, 0xD6, 0xA3, 0x1E, 0x53, 0x3D, 0x29,
  0x29, 0xCA, 0x51, 0x59, 0x6A, 0xE1, 0x47, 0x05,
  0x0F, 0xC4, 0x5A, 0xDC, 0x8C, 0xDF, 0xD9, 0x8D,
  0x6C, 0x5E, 0xBD, 0x7B, 0x2C, 0x7E, 0x0A, 0xF8,
 };

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
  printf("};\n");
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

// Most of the tests below require these variables
struct in_addr raw4addr;
struct in_addr anon4addr;

// Addresses in network-endian order
bool valid_ipv4_anon(unsigned int prefix,
                     struct in_addr *ipaddr,
                     struct in_addr *anonaddr) {
  assert(prefix <= 8 * sizeof(uint32_t));

  // Special case (0-prefix): both should be different
  if (prefix == 0) {
    return ipaddr->s_addr != anonaddr->s_addr;
  }

  // Special case (32-prefix): both should be the same
  if (prefix == 8 * sizeof(uint32_t)) {
    return ipaddr->s_addr == anonaddr->s_addr;
  }

  // Upper prefix should be the same and lower prefix should be different
  uint32_t upper = ~((uint32_t) 0) << (8 * sizeof(uint32_t) - prefix);
  uint32_t lower = ~upper;
  lower = htonl(lower);
  upper = htonl(upper);

  if ((upper & ipaddr->s_addr) == (upper & anonaddr->s_addr) &&
      (lower & ipaddr->s_addr) != (lower & anonaddr->s_addr)) {
    return true;
  }

  return false;
}


Ensure(ipanon_tests, anonymize_ipv4_returns_error_on_null) {
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  err = anonymizer.anonymize_ipv4(NULL, 14, &raw4addr, &anon4addr);
  assert_that(err, is_equal_to(IPANON_ERROR_NULL));
}


Ensure(ipanon_tests, anonymize_ipv4_returns_error_on_bad_prefix) {
  // Strategy: test negative and too many prefix
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  int rc = inet_pton(AF_INET, ipv4addr, &raw4addr);
  assert(rc == 1);

  err = anonymizer.anonymize_ipv4(&anonymizer, 33, &raw4addr, &anon4addr);
  assert_that(err, is_equal_to(IPANON_ERROR_ANON_PREFIX));
}


Ensure(ipanon_tests, anonymize_ipv4_returns_ok_on_good_prefix) {
  // Strategy: cycle through a set of prefixes, validating that anonymized
  // address is valid.
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  // Use predictable values for key and pad
  memcpy(anonymizer.private.key, state,
         sizeof(anonymizer.private.key));
  memcpy(anonymizer.private.key, state + sizeof(anonymizer.private.key),
         sizeof(anonymizer.private.pad));

  int rc = inet_pton(AF_INET, ipv4addr, &raw4addr);
  assert(rc == 1);

  for (unsigned int prefix = 0; prefix <= 8 * sizeof(uint32_t); ++prefix) {
    err = anonymizer.anonymize_ipv4(&anonymizer, prefix, &raw4addr, &anon4addr);
    assert_that(err, is_equal_to(IPANON_OK));
    assert_that(valid_ipv4_anon(prefix, &raw4addr, &anon4addr), is_true);
  }
}


Ensure(ipanon_tests, anonymize_ipv4_works_with_same_buffer_in_and_out) {
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  // Use predictable values for key and pad
  memcpy(anonymizer.private.key, state,
         sizeof(anonymizer.private.key));
  memcpy(anonymizer.private.key, state + sizeof(anonymizer.private.key),
         sizeof(anonymizer.private.pad));

  int rc = inet_pton(AF_INET, ipv4addr, &raw4addr);
  assert(rc == 1);

  for (unsigned int prefix = 0; prefix <= 8 * sizeof(uint32_t); ++prefix) {
    err = anonymizer.anonymize_ipv4(&anonymizer, prefix, &raw4addr, &anon4addr);
    assert(err == IPANON_OK);

    // Use temporary address for input and output buffers
    struct in_addr addr = raw4addr;
    err = anonymizer.anonymize_ipv4(&anonymizer, prefix, &addr, &addr);
    assert(err == IPANON_OK);

    // Verify that using two buffers or reusing one buffer makes no difference
    uint32_t anon_separate_buffers = anon4addr.s_addr;
    uint32_t anon_reuse_buffer = addr.s_addr;
    assert_that(anon_reuse_buffer, is_equal_to(anon_separate_buffers));
  }
}


//-------------------------------------------------------------------------------

// Most of the tests below require these variables
struct in6_addr raw6addr;
struct in6_addr anon6addr;


// Addresses in network-endian order
bool valid_ipv6_anon(unsigned int prefix,
                     struct in6_addr *ipaddr,
                     struct in6_addr *anonaddr) {
  assert(prefix <= 8 * sizeof(uint128_t));

  // Special case (0-prefix): both should be different
  if (prefix == 0) {
    return (*((uint128_t *) ipaddr->s6_addr) !=
            *((uint128_t *) anonaddr->s6_addr));
  }

  // Special case (128-prefix): both should be the same
  if (prefix == 8 * sizeof(uint128_t)) {
    return (*((uint128_t *) ipaddr->s6_addr) ==
            *((uint128_t *) anonaddr->s6_addr));
  }

  // Upper prefix should be the same and lower prefix should be different
  uint128_t upper = ~((uint128_t) 0) << (8 * sizeof(uint128_t) - prefix);
  uint128_t lower = ~upper;
  lower = htobe128(lower);
  upper = htobe128(upper);

  if ((upper & *((uint128_t *) ipaddr->s6_addr)) ==
      (upper & *((uint128_t *) anonaddr->s6_addr)) &&
      (lower & *((uint128_t *) ipaddr->s6_addr)) !=
      (lower & *((uint128_t *) anonaddr->s6_addr))) {
    return true;
  }

  return false;
}


Ensure(ipanon_tests, anonymize_ipv6_returns_error_on_null) {
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  err = anonymizer.anonymize_ipv6(NULL, 14, &raw6addr, &anon6addr);
  assert_that(err, is_equal_to(IPANON_ERROR_NULL));
}


Ensure(ipanon_tests, anonymize_ipv6_returns_error_on_bad_prefix) {
  // Strategy: test negative and too many prefix
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  int rc = inet_pton(AF_INET6, ipv6addr, &raw6addr);
  assert(rc == 1);

  err = anonymizer.anonymize_ipv6(&anonymizer, 129, &raw6addr, &anon6addr);
  assert_that(err, is_equal_to(IPANON_ERROR_ANON_PREFIX));
}


Ensure(ipanon_tests, anonymize_ipv6_returns_ok_on_good_prefix) {
  // Strategy: cycle through a set of prefixes, validating that anonymized
  // address is valid.
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  // Use predictable values for key and pad
  memcpy(anonymizer.private.key, state,
         sizeof(anonymizer.private.key));
  memcpy(anonymizer.private.key, state + sizeof(anonymizer.private.key),
         sizeof(anonymizer.private.pad));

  int rc = inet_pton(AF_INET6, ipv6addr, &raw6addr);
  assert(rc == 1);

  for (unsigned int prefix = 0; prefix <= 8 * sizeof(uint128_t); ) {
    err = anonymizer.anonymize_ipv6(&anonymizer, prefix, &raw6addr, &anon6addr);
    assert_that(err, is_equal_to(IPANON_OK));
    assert_that(valid_ipv6_anon(prefix, &raw6addr, &anon6addr), is_true);
    prefix += 1;
  }
}

Ensure(ipanon_tests, anonymize_ipv6_works_with_same_buffer_in_and_out) {
  ipanonymizer anonymizer;
  ipanon_errno err = ipanon_init(&anonymizer);
  assert(err == IPANON_OK);

  // Use predictable values for key and pad
  memcpy(anonymizer.private.key, state,
         sizeof(anonymizer.private.key));
  memcpy(anonymizer.private.key, state + sizeof(anonymizer.private.key),
         sizeof(anonymizer.private.pad));

  assert(inet_pton(AF_INET6, ipv6addr, &raw6addr) == 1);

  for (unsigned int prefix = 0; prefix <= 8 * sizeof(uint128_t); ++prefix) {
    err = anonymizer.anonymize_ipv6(&anonymizer, prefix, &raw6addr, &anon6addr);
    assert(err == IPANON_OK);

    // Use temporary address for input and output buffers
    struct in6_addr addr = raw6addr;
    err = anonymizer.anonymize_ipv6(&anonymizer, prefix, &addr, &addr);
    assert(err == IPANON_OK);

    // Verify that using two buffers or reusing one buffer makes no difference
    uint128_t anon_separate_buffers = *((uint128_t *) anon6addr.s6_addr);
    uint128_t anon_reuse_buffer = *((uint128_t *) addr.s6_addr);
    assert_that(anon_reuse_buffer, is_equal_to(anon_separate_buffers));
  }
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

    add_test_with_context(suite, ipanon_tests, anonymize_ipv4_returns_error_on_null);
    add_test_with_context(suite, ipanon_tests, anonymize_ipv4_returns_error_on_bad_prefix);
    add_test_with_context(suite, ipanon_tests, anonymize_ipv4_returns_ok_on_good_prefix);
    add_test_with_context(suite, ipanon_tests, anonymize_ipv4_works_with_same_buffer_in_and_out);

    add_test_with_context(suite, ipanon_tests, anonymize_ipv6_returns_error_on_null);
    add_test_with_context(suite, ipanon_tests, anonymize_ipv6_returns_error_on_bad_prefix);
    add_test_with_context(suite, ipanon_tests, anonymize_ipv6_returns_ok_on_good_prefix);
    add_test_with_context(suite, ipanon_tests, anonymize_ipv6_works_with_same_buffer_in_and_out);

    return suite;
}
