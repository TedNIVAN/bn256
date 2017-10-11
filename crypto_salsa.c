#include "crypto_salsa.h"

int crypto_salsa_onion_seal(uint8_t *c,
                            uint64_t *clen_p,
                            uint64_t mlen,
                            const uint8_t m[mlen],
                            uint64_t num_keys,
                            uint8_t pkeys[][32]) {

    if (!mlen || !num_keys) {
        return -1;
    }

    uint8_t *current_offset = c + (crypto_box_SEALBYTES * (num_keys - 1));
    uint64_t current_msg_len = mlen;
    crypto_box_seal(current_offset, m, current_msg_len, pkeys[num_keys - 1]);

    for (int i = 2; i <= num_keys; i++) {
        current_msg_len += crypto_box_SEALBYTES;
        current_offset -= crypto_box_SEALBYTES;
        crypto_box_seal(current_offset, current_offset + crypto_box_SEALBYTES, current_msg_len, pkeys[num_keys - i]);
    }

    if (clen_p) {
        *clen_p = mlen + (crypto_box_SEALBYTES * num_keys);
    }
    return 0;
}

int crypto_salsa_encrypt(uint8_t *c, uint64_t mlen, const uint8_t m[mlen], const uint8_t *k) {
    randombytes_buf(c, crypto_secretbox_NONCEBYTES);
    return crypto_secretbox_easy(c + crypto_secretbox_NONCEBYTES, m, mlen, c, k);
}

int crypto_salsa_decrypt(uint8_t *msg, uint64_t clen, const uint8_t *c, const uint8_t *k) {
    return crypto_secretbox_open_easy(msg, c + crypto_secretbox_NONCEBYTES, clen - crypto_secretbox_NONCEBYTES, c, k);
}
