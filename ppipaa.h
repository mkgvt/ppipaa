/*
-- The ppipaa IP address anonymization library
--
-- Performs full or partial anonymization of IP addresses using the CryptopAN
-- algorithm using modern cryptographic primitives from libsodium which are
-- well supported on both high and low end processors.
--
-- Copyright (C) 2020, Mark Gardner <mkg@vt.edu>.
--
-- This file is part of ppipaa.
--
-- ppipaa is free software: you can redistribute it and/or modify it under the
-- terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option)
-- any later version.
--
-- ppipaa is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
-- FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
-- more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with ppipaa. If not, see <https://www.gnu.org/licenses/>.
*/
#ifndef __IPCRYPTO_H
#define __IPCRYPTO_H

#include <netinet/in.h>
#include <sodium.h>


typedef enum {
  PPIPAA_OK,                    // No error
  PPIPAA_ERROR_NULL,            // Anonymizer is NULL
  PPIPAA_ERROR_INIT,            // Initialization failed
  PPIPAA_ERROR_DEINIT,          // Deinitialization failed
  PPIPAA_ERROR_EXTERN,          // Externalization failed
  PPIPAA_ERROR_INTERN,          // Internalization failed
  PPIPAA_ERROR_ANON_PREFIX,     // Invalid prefix bits in anonymize call
  PPIPAA_ERROR_ANON_ADDR_NULL,  // Plaintext or anonymized addr ptr is NULL
  PPIPAA_ERROR_ANON_PRF_FAIL,   // Pseudo-random function failed
  PPIPAA_END_OF_ERRORS,         // indicates end of errors (must be last)
} ppipaa_errno;


typedef struct ppipaa_state ppipaaymizer;

struct ppipaa_state {
  // Public interface

  /*
  -- (Re)-initialize the anonymizer.
  --
  -- Returns PPIPAA_OK or PPIPAA_ERROR_INIT.
  --
  -- NOTE: caller is responsible for managing the storage on the stack or heap.
  */
  ppipaa_errno (*init)(ppipaaymizer *anonymizer);

  /*
  -- De-initialize the anonymizer.
  --
  -- Returns PPIPAA_OK or PPIPAA_ERROR_DEINIT.
  --
  -- NOTE: storage can be freed or reused after successful deinit.
  */
  ppipaa_errno (*deinit)(ppipaaymizer *anonymizer);

  /*
  -- Externalize the anonymizer state.
  --
  -- Externalized state can be restored later so that different runs anonymize
  -- IP addresses consistently. The externalized state is encrypted with a key
  -- to protect confidentiality and integrity.
  --
  -- Returns PPIPAA_OK or PPIPAA_ERROR_EXTERNALIZE.
  --
  -- Note: only bytes are written; all other file management is the caller's
  --       responsibility.

  */
  ppipaa_errno (*externalize)(ppipaaymizer *anonymizer, FILE *out,
                              char *key, int keylen);

  /*
  -- Internalize the anonymizer state.
  --
  -- Restoring externalized state allows different runs to anonymize IP
  -- addresses consistently. The same encryption key used during
  -- externalization must be used.
  --
  -- Returns PPIPAA_OK or PPIPAA_ERROR_INTERNALIZE.
  --
  -- Note: only bytes are read; all other file management is the caller's
  --       responsibility.
  */
  ppipaa_errno (*internalize)(ppipaaymizer *anonymizer, FILE *in,
                              char *key, int keylen);


  /*
  -- Anonymize the IPv4 address.
  --
  -- Returns PPIPAA_OK or PPIPAA_ERROR_ANON_xxxx.
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
  ppipaa_errno (*anonymize_ipv4)(ppipaaymizer *anonymizer,
                                 unsigned int prefix,
                                 struct in_addr *ipaddr,
                                 struct in_addr *anonaddr);

  /*
  -- Anonymize the IPv6 address.
  --
  -- Returns PPIPAA_OK or PPIPAA_ERROR_ANON_xxxx.
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
  ppipaa_errno (*anonymize_ipv6)(ppipaaymizer *anonymizer,
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
-- Returns PPIPAA_OK or PPIPAA_ERROR_INIT.
--
-- NOTE: caller is responsible for managing the storage on the stack or heap.
*/
extern ppipaa_errno ppipaa_init(ppipaaymizer *anonymizer);


/*
-- Helper: return size of saved anonymizer state.
--
-- Useful in allocating buffer space for externalization and internalization;
*/
extern size_t ppipaa_saved_state_size(void);


#endif // __IPCRYPTO_H
