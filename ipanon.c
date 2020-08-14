#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "ipanon.h"

// Length of externalized data
#define CIPHERTEXT_LEN (crypto_generichash_KEYBYTES + crypto_secretbox_MACBYTES)


/*
-- Helper: return size of saved anonymizer state.
--
-- Useful in allocating buffer space for externalization;
*/
size_t ipanon_saved_state_size(void) {
  return crypto_pwhash_SALTBYTES +
         crypto_secretbox_NONCEBYTES +
         crypto_generichash_KEYBYTES +
         crypto_secretbox_MACBYTES;
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
  int cnt = fwrite(anonymizer->_key, sizeof(anonymizer->_key), 1, out);
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
                            anonymizer->_key, sizeof(anonymizer->_key),
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
  int cnt = fread(anonymizer->_key, sizeof(anonymizer->_key), 1, in);
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
  if (crypto_secretbox_open_easy(anonymizer->_key,
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
  anonymizer->externalize = ipanon_externalize;
  anonymizer->internalize = ipanon_internalize;

  return IPANON_OK;
}
