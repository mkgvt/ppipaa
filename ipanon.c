/*
-- The ipanon IP address anonymization library
--
-- Performs full or partial anonymization of IP addresses using the CryptopAN
-- algorithm using modern cryptographic primitives from libsodium which are
-- well supported on both high and low end processors.
--
-- Copyright (C) 2020, Mark Gardner <mkg@vt.edu>.
--
-- This file is part of ipanon.
--
-- ipanon is free software: you can redistribute it and/or modify it under the
-- terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option)
-- any later version.
--
-- ipanon is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-- FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
-- more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with ipanon. If not, see <https://www.gnu.org/licenses/>.
*/
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ipanon.h"
#include "uint128.h"

// Length of externalized data
#define CIPHERTEXT_LEN (crypto_generichash_KEYBYTES + \
                        crypto_generichash_BYTES + \
                        crypto_secretbox_MACBYTES)


/*
-- Anonymize the IPv4 address.
--
-- Returns IPANON_OK or IPANON_ERROR_ANON_xxxx.
--
-- NOTE:
--
-- - ipaddr and anonaddr are in network order
--
-- - prefix specifies the number of bits in the prefix to leave
--   unanonymized: prefix=0 means anonymize all bits, prefix=32 means
--   no bits.
--
-- - the input and output address buffers can be the same for
--   conversion in place.
*/
ipanon_errno ipanon_anonymize_ipv4(ipanonymizer *anonymizer,
                                   unsigned int prefix,
                                   struct in_addr *ipaddr,
                                   struct in_addr *anonaddr) {
  // Strategy: anonymize the whole IP address then overwrite the upper bits
  // with the original IP address prefix. This maintains the prefix-preserving
  // nature of anonymization while allowing partial anonymization. Always
  // doing the anonymization eliminates a potential side-channel attack.

  if (anonymizer == NULL) {
    return IPANON_ERROR_NULL;
  }
  if (prefix > 8 * sizeof(uint32_t)) {
    return IPANON_ERROR_ANON_PREFIX;
  }
  if (ipaddr == NULL || anonaddr == NULL) {
    return IPANON_ERROR_ANON_ADDR_NULL;
  }

  // Prefix-preserving anonymization is of the form:
  //
  // f_i(a_1 a_2 ... a_i) := L(R(P(a_1 a_2 ... a_i), k)
  //
  // where L returns the least-significant bit, R is the pseudo random
  // function, P is the pad function, and k is the key used by the PRF.
  //
  // See equation 2: Xu, Fan, Ammar, and Moon, "Prefix-Preserving IP Address
  // Anonymization: Measurement-based Security Evaluation and a New
  // Cryptography-based Scheme", in the Proceedins of the 10th IEEE
  // International Conference on Network Protocols, Paris France, 2002.
  // https://www.cc.gatech.edu/computing/Networking/projects/cryptopan/icnp02.ps
  //
  // Note: the loop operates on host-endian addresses for performance.
  uint32_t ip = ntohl(ipaddr->s_addr);
  uint32_t ones = ~((uint32_t) 0);
  uint32_t pad = *((uint32_t *) anonymizer->private.pad);
  uint32_t accum = 0;
  for (int shift = 8 * sizeof(uint32_t) - 1; shift >= 0; --shift) {
    uint32_t upper = ones << shift;
    uint32_t lower = ~upper;
    uint32_t tohash = (ip & upper) | (pad & lower);

    unsigned char hash[crypto_generichash_BYTES];
    if (crypto_generichash(hash, sizeof(hash), (unsigned char *) &tohash, sizeof(tohash),
                           anonymizer->private.key, sizeof(anonymizer->private.key)) != 0) {
      return IPANON_ERROR_ANON_PRF_FAIL;
    }
    uint32_t bit = hash[0] & ((uint8_t) 1);
    accum |= bit << shift;
  }

  // Combine prefix (upper) bits with anonymized (lower) bits
  uint32_t lower = ones >> prefix;
  if (prefix == 8 * sizeof(uint32_t)) {
    // Be explicit because logical shift >= #bits is undefined
    lower = 0;
  }
  uint32_t upper = ~lower;
  uint32_t addr = (ip & upper) | (accum & lower);
  anonaddr->s_addr = htonl(addr);

  return IPANON_OK;
}


/*
-- Anonymize the IPv6 address.
--
-- Returns IPANON_OK or IPANON_ERROR_ANON_xxxx.
--
-- NOTE:
--
-- - ipaddr and anonaddr are in network order
--
-- - prefix specifies the number of bits in the prefix to leave
--   unanonymized: prefix=0 means anonymize all bits, prefix=128 means
--   no bits.
--
-- - the input and output address buffers can be the same for
--   conversion in place.
*/
ipanon_errno ipanon_anonymize_ipv6(ipanonymizer *anonymizer,
                                   unsigned int prefix,
                                   struct in6_addr *ipaddr,
                                   struct in6_addr *anonaddr) {
  // Strategy: anonymize the whole IP address then overwrite the upper bits
  // with the original IP address prefix. This maintains the prefix-preserving
  // nature of anonymization while allowing partial anonymization.

  if (anonymizer == NULL) {
    return IPANON_ERROR_NULL;
  }
  if (prefix > 8 * sizeof(uint128_t)) {
    return IPANON_ERROR_ANON_PREFIX;
  }
  if (ipaddr == NULL || anonaddr == NULL) {
    return IPANON_ERROR_ANON_ADDR_NULL;
  }

  // Prefix-preserving anonymization is of the form:
  //
  // f_i(a_1 a_2 ... a_i) := L(R(P(a_1 a_2 ... a_i), k)
  //
  // where L returns the least-significant bit, R is the pseudo random
  // function, P is the pad function, and k is the key used by the PRF.
  //
  // See equation 2: Xu, Fan, Ammar, and Moon, "Prefix-Preserving IP Address
  // Anonymization: Measurement-based Security Evaluation and a New
  // Cryptography-based Scheme", in the Proceedins of the 10th IEEE
  // International Conference on Network Protocols, Paris France, 2002.
  // https://www.cc.gatech.edu/computing/Networking/projects/cryptopan/icnp02.ps
  //
  // Note: the loop operates on host-endian addresses for performance.
  uint128_t ip = be128toh(*((uint128_t*) &ipaddr->s6_addr));
  uint32_t  zeroarray[4] = { 0, 0, 0, 0 };
  uint128_t zeros = make_uint128(zeroarray);
  uint128_t accum = zeros;
  uint128_t ones = ~zeros;
  uint128_t pad;  // also inhost-endian order
  memcpy(&pad, anonymizer->private.pad, sizeof(pad));

  for (int shift = 8 * sizeof(uint128_t) - 1; shift >= 0; --shift) {
    uint128_t upper = ones << shift;
    uint128_t lower = ~upper;
    uint128_t tohash = (ip & upper) | (pad & lower);

    unsigned char hash[crypto_generichash_BYTES];
    if (crypto_generichash(hash, sizeof(hash), (unsigned char *) &tohash, sizeof(tohash),
                           anonymizer->private.key, sizeof(anonymizer->private.key)) != 0) {
      return IPANON_ERROR_ANON_PRF_FAIL;
    }
    uint128_t bit = hash[0] & ((uint8_t) 1);
    accum |= bit << shift;
  }

  uint128_t lower = ones >> prefix;
  if (prefix == 8 * sizeof(uint128_t)) {
    // Be explicit because logical shift >= #bits is undefined
    lower = 0;
  }
  uint128_t upper = ~lower;
  uint128_t addr = (ip & upper) | (accum & lower);
  *((uint128_t *) anonaddr->s6_addr) = be128toh(addr);

  return IPANON_OK;
}


/*
-- Helper: return size of saved anonymizer state.
--
-- Useful in allocating buffer space for externalization;
*/
size_t ipanon_saved_state_size(void) {
  return crypto_pwhash_SALTBYTES +
         crypto_secretbox_NONCEBYTES +
         CIPHERTEXT_LEN;
}


/*
-- Externalize the anonymizer state (plaintext).
--
-- Externalized state can be restored later so that different runs anonymize
-- IP addresses consistently. The externalized state is encrypted with a key
-- to protect confidentiality and integrity.
--
-- Returns IPANON_OK or IPANON_ERROR_EXTERNALIZE.
--
-- Note: only bytes are written; all other file management is the caller's
-- responsibility.
*/
static ipanon_errno ipanon_externalize_plaintext(ipanonymizer *anonymizer,
                                                 FILE *out) {
  // Sanity check
  if (anonymizer == NULL) {
    return IPANON_ERROR_NULL;
  }

  // Write out state.
  int cnt = fwrite(&anonymizer->private, sizeof(anonymizer->private), 1, out);
  if (cnt != 1) {
    return IPANON_ERROR_EXTERN;
  }

  return IPANON_OK;
}


/*
-- Externalize the anonymizer state (encrypted).
--
-- Externalized state can be restored later so that different runs anonymize
-- IP addresses consistently. The externalized state is encrypted with a key
-- to protect confidentiality and integrity.
--
-- Returns IPANON_OK or IPANON_ERROR_EXTERNALIZE.
--
-- Note: only bytes are written; all other file management is the caller's
-- responsibility.
*/
static ipanon_errno ipanon_externalize_encrypted(ipanonymizer *anonymizer,
                                                 FILE *out,
                                                 char *key, int keylen) {
  // Sanity check
  if (anonymizer == NULL) {
    return IPANON_ERROR_NULL;
  }

  // Prepare salt
  unsigned char salt[crypto_pwhash_SALTBYTES];
  randombytes_buf(salt, sizeof(salt));

  // Prepare the key.
  //
  // Note: ops limit, mem limit, and hash algorithm have to be the same for
  // externalization and internalization.
  unsigned char realkey[crypto_secretbox_KEYBYTES];
  if (crypto_pwhash(realkey, sizeof(realkey),
                    key, keylen, salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    // Typically: out of memory
    return IPANON_ERROR_EXTERN;
  }

  // Prepare the nonce
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  randombytes_buf(nonce, sizeof(nonce));

  // Encrypt the internal state.
  //
  // See https://doc.libsodium.org/secret-key_cryptography/secretbox
  unsigned char ciphertext[CIPHERTEXT_LEN];
  if (crypto_secretbox_easy(ciphertext,
                            (unsigned char *) &anonymizer->private,
                            sizeof(anonymizer->private),
                            nonce, realkey) != 0) {
    // Encryption failed
    return IPANON_ERROR_EXTERN;
  }

  // Write out salt.
  int cnt = fwrite(salt, sizeof(salt), 1, out);
  if (cnt != 1) {
    return IPANON_ERROR_EXTERN;
  }

  // Write out nonce.
  cnt = fwrite(nonce, sizeof(nonce), 1, out);
  if (cnt != 1) {
    return IPANON_ERROR_EXTERN;
  }

  // Write out encrypted state.
  cnt = fwrite(ciphertext, sizeof(ciphertext), 1, out);
  if (cnt != 1) {
    return IPANON_ERROR_EXTERN;
  }
  if (fflush(out) != 0) {
    return IPANON_ERROR_EXTERN;
  }

  return IPANON_OK;
}


/*
-- Externalize the anonymizer state.
--
-- Externalized state can be restored later so that different runs anonymize
-- IP addresses consistently. The externalized state is encrypted with a key
-- to protect confidentiality and integrity.
--
-- Returns IPANON_OK or IPANON_ERROR_EXTERNALIZE.
--
-- Note: only bytes are written; all other file management is the caller's
-- responsibility.
*/
static ipanon_errno ipanon_externalize(ipanonymizer *anonymizer, FILE *out,
                                       char *key, int keylen) {
  if (key == NULL) {
    return ipanon_externalize_plaintext(anonymizer, out);
  } else {
    return ipanon_externalize_encrypted(anonymizer, out, key, keylen);
  }
}


/*
-- Internalize the anonymizer state (plaintext).
--
-- Restoring externalized state allows different runs to anonymize IP
-- addresses consistently. The same encryption key used during
-- externalization must be used.
--
-- Returns IPANON_OK or IPANON_ERROR_INTERNALIZE.
--
-- Note: only bytes are read; all other file management is the caller's
-- responsibility.
*/
static ipanon_errno ipanon_internalize_plaintext(ipanonymizer *anonymizer,
                                                 FILE *in) {
  // Sanity check
  if (anonymizer == NULL) {
    return IPANON_ERROR_NULL;
  }

  // Read in state.
  int cnt = fread(&anonymizer->private, sizeof(anonymizer->private), 1, in);
  if (cnt != 1) {
    return IPANON_ERROR_INTERN;
  }

  return IPANON_OK;
}


/*
-- Internalize the anonymizer state (encrypted).
--
-- Restoring externalized state allows different runs to anonymize IP
-- addresses consistently. The same encryption key used during
-- externalization must be used.
--
-- Returns IPANON_OK or IPANON_ERROR_INTERNALIZE.
--
-- Note: only bytes are read; all other file management is the caller's
-- responsibility.
*/
static ipanon_errno ipanon_internalize_encrypted(ipanonymizer *anonymizer,
                                                 FILE *in,
                                                 char *key, int keylen) {
  // Sanity check
  if (anonymizer == NULL) {
    return IPANON_ERROR_NULL;
  }

  // Read in salt.
  unsigned char salt[crypto_pwhash_SALTBYTES];
  int cnt = fread(salt, sizeof(salt), 1, in);
  if (cnt != 1) {
    return IPANON_ERROR_INTERN;
  }

  // Read in nonce.
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  cnt = fread(nonce, sizeof(nonce), 1, in);
  if (cnt != 1) {
    return IPANON_ERROR_INTERN;
  }

  // Read in encrypted state.
  unsigned char ciphertext[CIPHERTEXT_LEN];
  cnt = fread(ciphertext, sizeof(ciphertext), 1, in);
  if (cnt != 1) {
    return IPANON_ERROR_INTERN;
  }

  // Prepare the key.
  //
  // Note: ops limit, mem limit, and hash algorithm have to be the same for
  // externalization and internalization.
  unsigned char realkey[crypto_secretbox_KEYBYTES];
  if (crypto_pwhash(realkey, sizeof(realkey),
                    key, keylen, salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    // Typically: out of memory
    return IPANON_ERROR_EXTERN;
  }

  // Decrypt the internal state.
  //
  // See https://doc.libsodium.org/secret-key_cryptography/secretbox
  if (crypto_secretbox_open_easy((unsigned char *) &anonymizer->private,
                                 ciphertext, CIPHERTEXT_LEN,
                                 nonce, realkey) != 0) {
    // Encryption failed
    return IPANON_ERROR_INTERN;
  }

  return IPANON_OK;
}


/*
-- Internalize the anonymizer state.
--
-- Restoring externalized state allows different runs to anonymize IP
-- addresses consistently. The same encryption key used during
-- externalization must be used.
--
-- Returns IPANON_OK or IPANON_ERROR_INTERNALIZE.
--
-- Note: only bytes are read; all other file management is the caller's
-- responsibility.
*/
static ipanon_errno ipanon_internalize(ipanonymizer *anonymizer,
                                       FILE *in, char *key, int keylen) {
  if (key == NULL) {
    return ipanon_internalize_plaintext(anonymizer, in);
  } else {
    return ipanon_internalize_encrypted(anonymizer, in, key, keylen);
  }
}


/*
--  De-initialize the anonymizer.
--
-- Returns IPANON_OK or IPANON_ERROR_DEINIT.
--
-- NOTE: storage can be freed or reused after successful deinit.
*/
static ipanon_errno ipanon_deinit(ipanonymizer *anonymizer) {
  // Sanity check
  if (anonymizer == NULL) {
    return IPANON_ERROR_NULL;
  }

  // Nothing really needed but clear the key for security.
  memset(anonymizer->private.key, 0, sizeof(anonymizer->private.key));
  memset(anonymizer->private.pad, 0, sizeof(anonymizer->private.pad));

  return IPANON_OK;
}


/*
-- Initialize the anonymizer.
--
-- Returns IPANON_OK or IPANON_ERROR_INIT.
--
-- NOTE: caller is responsible for managing the storage on the stack or heap.
*/
ipanon_errno ipanon_init(ipanonymizer *anonymizer) {
  // Sanity check
  if (anonymizer == NULL) {
    return IPANON_ERROR_NULL;
  }

  // Note: sodium_init is re-entrant
  if (sodium_init() < 0) {
    return IPANON_ERROR_INIT;
  }
  randombytes_buf(anonymizer->private.key, sizeof(anonymizer->private.key));
  randombytes_buf(anonymizer->private.pad, sizeof(anonymizer->private.pad));

  // Set up "methods"
  anonymizer->init = ipanon_init;
  anonymizer->deinit = ipanon_deinit;
  anonymizer->externalize = ipanon_externalize;
  anonymizer->internalize = ipanon_internalize;
  anonymizer->anonymize_ipv4 = ipanon_anonymize_ipv4;
  anonymizer->anonymize_ipv6 = ipanon_anonymize_ipv6;

  return IPANON_OK;
}
