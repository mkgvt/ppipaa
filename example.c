#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include "ppipaa.h"

const char *IPADDRESS = "198.51.100.47";
const unsigned int PREFIX = 16;

void display(unsigned int prefix,
             char *tag, struct in_addr *origaddr,
             struct in_addr *anonaddr) {
  char str1[16], str2[16];
  printf("%s: prefix=%u original=%-15s 0x%08X -> anonymized=%-15s 0x%08X\n",
         tag, prefix,
         inet_ntop(AF_INET, origaddr, str1, sizeof(str1)),
         ntohl(origaddr->s_addr),
         inet_ntop(AF_INET, anonaddr, str2, sizeof(str2)),
         ntohl(anonaddr->s_addr));
}

int main(void) {
  // Get address to anonymize
  struct in_addr origaddr;
  int rc = inet_pton(AF_INET, IPADDRESS, &origaddr);
  assert(rc == 1);

  // Initialize anonymizer
  ipanonymizer anonymizer;
  ppipaa_errno err = ppipaa_init(&anonymizer);
  assert(err == PPIPAA_OK);

  // Anonymize address
  struct in_addr anonaddr;
  err = anonymizer.anonymize_ipv4(&anonymizer, PREFIX, &origaddr, &anonaddr);
  assert(err == PPIPAA_OK);
  display(PREFIX, "Key1", &origaddr, &anonaddr);

  // Externalize (save) state (to string "file")
  unsigned char buf[ppipaa_saved_state_size() + 1];
  FILE *out = fmemopen(buf, sizeof(buf), "w");
  err = anonymizer.externalize(&anonymizer, out, NULL, 0);
  assert(err == PPIPAA_OK);
  fclose(out);

  // Deinit and re-init with a different state
  err = anonymizer.deinit(&anonymizer);
  assert(err == PPIPAA_OK);
  err = ppipaa_init(&anonymizer);
  assert(err == PPIPAA_OK);

  // Anonymize address with new key
  err = anonymizer.anonymize_ipv4(&anonymizer, PREFIX, &origaddr, &anonaddr);
  assert(err == PPIPAA_OK);
  display(PREFIX, "Key2", &origaddr, &anonaddr);

  // Internalize (restore) state (from string "file")
  FILE *in = fmemopen(buf, sizeof(buf), "r");
  err = anonymizer.internalize(&anonymizer, in, NULL, 0);
  assert(err == PPIPAA_OK);
  fclose(in);

  // Anonymize address with original key
  err = anonymizer.anonymize_ipv4(&anonymizer, PREFIX, &origaddr, &anonaddr);
  assert(err == PPIPAA_OK);
  display(PREFIX, "Key1", &origaddr, &anonaddr);

  return 0;
}
