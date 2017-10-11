#include <string.h>
#include "bn256_ibe.h"

int main() {
    if (sodium_init() < 0) {
        exit(EXIT_FAILURE);
    }

    if (bn256_init() < 0) {
        exit(EXIT_FAILURE);
    }

    g1_t master_pk;
    scalar_t master_sk;
    bn256_ibe_master_keypair(master_sk, master_pk);

    unsigned char id[] = "chris";
    size_t id_len = strlen((char*)id);
    unsigned char m[] = "This is a test message";
    size_t mlen = sizeof m;

    uint8_t ciphertext[mlen + bn256_ibe_ABYTES];
    bn256_ibe_encrypt(ciphertext, mlen, m, master_pk, id, id_len);

    g2_t id_sk;
    uint8_t hashed_id[g2_bytes];
    bn256_ibe_keygen(id_sk, hashed_id, id, id_len, master_sk);

    uint8_t plaintext[mlen];
    bn256_ibe_decrypt(plaintext, ciphertext, sizeof ciphertext, hashed_id, id_sk);

    printf("Decrypted: %s\n", plaintext);
}