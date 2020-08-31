/*
-- ipanon: IP anonymization library
--
-- Performs full or partial anonymization of IP addresses using the CryptopAN
-- algorithm using modern cryptographic primitives from libsodium which are
-- well supported on both high and low end processors.
*/
#ifndef __IPCRYPTO_H
#define __IPCRYPTO_H

#include <netinet/in.h>
#include <sodium.h>


typedef enum {
  IPANON_OK,             // No error
  IPANON_ERROR_NULL,     // Anonymizer is NULL
  IPANON_ERROR_INIT,     // Initialization failed
  IPANON_ERROR_DEINIT,   // Deinitialization failed
  IPANON_ERROR_EXTERN,   // Externalization failed
  IPANON_ERROR_INTERN,   // Internalization failed
  IPANON_END_OF_ERRORS,  // sentinel indicating end of errors (must be last)
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

  // Private internals: do not access them directly
  struct private {
    unsigned char key[crypto_generichash_KEYBYTES];
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
