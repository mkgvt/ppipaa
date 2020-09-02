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
#ifndef __IPCRYPTO_H
#define __IPCRYPTO_H

#include <netinet/in.h>
#include <sodium.h>


typedef enum {
  IPANON_OK,                    // No error
  IPANON_ERROR_NULL,            // Anonymizer is NULL
  IPANON_ERROR_INIT,            // Initialization failed
  IPANON_ERROR_DEINIT,          // Deinitialization failed
  IPANON_ERROR_EXTERN,          // Externalization failed
  IPANON_ERROR_INTERN,          // Internalization failed
  IPANON_ERROR_ANON_PREFIX,     // Invalid prefix bits in anonymize call
  IPANON_ERROR_ANON_ADDR_NULL,  // Plaintext or anonymized addr ptr is NULL
  IPANON_ERROR_ANON_PRF_FAIL,   // Pseudo-random function failed
  IPANON_END_OF_ERRORS,         // indicates end of errors (must be last)
} ipanon_errno;


typedef struct ipanon_state ipanonymizer;

struct ipanon_state {
  // Public interface

  /*
  -- (Re)-initialize the anonymizer.
  --
  -- Returns IPANON_OK or IPANON_ERROR_INIT.
  --
  -- NOTE: caller is responsible for managing the storage on the stack or heap.
  */
  ipanon_errno (*init)(ipanonymizer *anonymizer);

  /*
  -- De-initialize the anonymizer.
  --
  -- Returns IPANON_OK or IPANON_ERROR_DEINIT.
  --
  -- NOTE: storage can be freed or reused after successful deinit.
  */
  ipanon_errno (*deinit)(ipanonymizer *anonymizer);

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
  --       responsibility.

  */
  ipanon_errno (*externalize)(ipanonymizer *anonymizer, FILE *out,
                              char *key, int keylen);

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
  --       responsibility.
  */
  ipanon_errno (*internalize)(ipanonymizer *anonymizer, FILE *in,
                              char *key, int keylen);


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
  ipanon_errno (*anonymize_ipv4)(ipanonymizer *anonymizer,
                                 unsigned int prefix,
                                 struct in_addr *ipaddr,
                                 struct in_addr *anonaddr);

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
  ipanon_errno (*anonymize_ipv6)(ipanonymizer *anonymizer,
                                 unsigned int prefix,
                                 struct in6_addr *ipaddr,
                                 struct in6_addr *anonaddr);


  // Private internals: do not access them directly
  struct private {
    unsigned char key[crypto_generichash_KEYBYTES];
    unsigned char pad[crypto_generichash_BYTES];
  } private;
};


/*
-- Initialize the anonymizer.
--
-- Returns IPANON_OK or IPANON_ERROR_INIT.
--
-- NOTE: caller is responsible for managing the storage on the stack or heap.
*/
extern ipanon_errno ipanon_init(ipanonymizer *anonymizer);


/*
-- Helper: return size of saved anonymizer state.
--
-- Useful in allocating buffer space for externalization and internalization;
*/
extern size_t ipanon_saved_state_size(void);


#endif // __IPCRYPTO_H
