#ifndef BN256_IBE_H
#define BN256_IBE_H

#include "bn256.h"
#include "crypto_salsa.h"


#define bn256_ibe_ABYTES (g1_bytes + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)

void bn256_ibe_master_keypair(scalar_t sk, curvepoint_fp_struct_t *pk);

int bn256_ibe_encrypt(uint8_t *out, uint64_t mlen, uint8_t *m, g1_t master_pk, uint8_t *id, size_t id_len);

int bn256_ibe_decrypt(uint8_t *out, uint8_t *c, size_t clen, uint8_t *id_hash, g2_t sk);

void bn256_ibe_keygen(g2_t id_sk, uint8_t *id_pk_p, uint8_t *id, size_t id_len, scalar_t master_sk);

#endif //BN256_IBE_H
