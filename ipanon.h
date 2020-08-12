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
  IPANON_ERROR_INIT,     // Initialization failed
  IPANON_ERROR_DEINIT,   // Deinitialization failed
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
  
  // Private internals: do not access them directly
  unsigned char _key[crypto_generichash_KEYBYTES];
};


/*
-- Initialize the anonymizer.
--
-- Returns IPANON_OK or IPANON_ERROR_INIT.
--
-- NOTE: caller is responsible for managing the storage on the stack or heap.
*/
extern ipanon_errno ipanon_init(ipanonymizer *anonymizer);


#endif // __IPCRYPTO_H
