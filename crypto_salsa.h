#ifndef CRYPTO_SALSA_H
#define CRYPTO_SALSA_H

#include <stdint.h>
#include <sodium.h>

int crypto_salsa_onion_seal(uint8_t *c,
                            uint64_t *clen_p,
                            uint64_t mlen,
                            const uint8_t m[mlen],
                            uint64_t num_keys,
                            uint8_t pkeys[num_keys][crypto_box_PUBLICKEYBYTES]);

int crypto_salsa_decrypt(uint8_t *msg, uint64_t clen, const uint8_t c[clen], const uint8_t *k);
int crypto_salsa_encrypt(uint8_t *c, uint64_t mlen, const uint8_t m[mlen], const uint8_t *k);

#endif //CRYPTO_SALSA_H
