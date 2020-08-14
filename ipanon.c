#include <string.h>

#include "ipanon.h"

/*
-- ipanon: IP anonymization library
--
-- Performs full or partial anonymization of IP addresses using the CryptopAN
-- algorithm using modern cryptographic primitives which are well supported on
-- both high- and low-end processors.
*/
#include "ipanon.h"


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
  memset(anonymizer->_key, 0, sizeof(anonymizer->_key));

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
  randombytes_buf(anonymizer->_key, sizeof(anonymizer->_key));

  // Set up "methods"
  anonymizer->init = ipanon_init;
  anonymizer->deinit = ipanon_deinit;

  return IPANON_OK;
}
