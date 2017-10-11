#include "bn256_ibe.h"

static inline void bn256_ibe_build_sk(uint8_t *out, uint8_t *id_hash, uint8_t *rp, uint8_t *pair_hash);

void bn256_ibe_master_keypair(scalar_t sk, g1_t pk) {
    bn256_g1_random(pk, sk);
}

static inline void bn256_ibe_build_sk(uint8_t *out, uint8_t *id_hash, uint8_t *rp, uint8_t *pair_hash) {
    crypto_generichash_state hash_state;
    crypto_generichash_init(&hash_state, 0, 0, crypto_secretbox_KEYBYTES);
    crypto_generichash_update(&hash_state, id_hash, g2_bytes);
    crypto_generichash_update(&hash_state, rp, g1_bytes);
    crypto_generichash_update(&hash_state, pair_hash, gt_bytes);
    crypto_generichash_final(&hash_state, out, crypto_secretbox_KEYBYTES);
}

int bn256_ibe_decrypt(uint8_t *out, uint8_t *c, size_t clen, uint8_t *id_hash, g2_t sk) {
    g1_t rp = {{{{{0}}}}};
    bn256_deserialize_g1(rp, c);

    fp12e_t pairing;
    fp12e_setzero(pairing);
    bn256_pair(pairing, sk, rp);

    uint8_t pairing_bytes[gt_bytes];
    bn256_serialize_gt(pairing_bytes, pairing);

    uint8_t secret_key[crypto_secretbox_KEYBYTES];
    bn256_ibe_build_sk(secret_key, id_hash, c, pairing_bytes);

    int result = crypto_salsa_decrypt(out, clen - g1_bytes, c + g1_bytes, secret_key);
    sodium_memzero(secret_key, sizeof secret_key);
    return result;
}

int bn256_ibe_encrypt(uint8_t *out, uint64_t mlen, uint8_t m[mlen], g1_t master_pk, uint8_t *id, size_t id_len) {
    g2_t id_hash;
    bn256_hash_g2(id_hash, id_len, id);
    uint8_t id_hash_bytes[g2_bytes];
    bn256_serialize_g2(id_hash_bytes, id_hash);

    scalar_t r;
    g1_t rp;
    bn256_g1_random(rp, r);
    bn256_serialize_g1(out, rp);

    fp12e_t pairing;
    fp12e_setzero(pairing);
    bn256_pair(pairing, id_hash, master_pk);

    fp12e_pow_vartime(pairing, pairing, r);
    uint8_t pairing_bytes[gt_bytes];
    bn256_serialize_gt(pairing_bytes, pairing);

    uint8_t secret_key[crypto_secretbox_KEYBYTES];
    bn256_ibe_build_sk(secret_key, id_hash_bytes, out, pairing_bytes);

    int result = crypto_salsa_encrypt(out + g1_bytes, mlen, m, secret_key);
    sodium_memzero(secret_key, sizeof secret_key);
    return result;
}

void bn256_ibe_keygen(g2_t id_sk, uint8_t *id_pk_p, uint8_t *id, size_t id_len, scalar_t master_sk) {
    g2_t id_pk;
    bn256_hash_g2(id_pk, id_len, id);
    bn256_serialize_g2(id_pk_p, id_pk);
    twistpoint_fp2_scalarmult_vartime(id_sk, id_pk, master_sk);
    twistpoint_fp2_makeaffine(id_sk);
}

