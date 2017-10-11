#ifndef BN256_BLS_H
#define BN256_BLS_H
#include "bn256.h"

int bn256_bls_verify_multisig(g2_struct *public_keys,
                              size_t num_participants,
                              uint8_t *signatures,
                              uint8_t *msg,
                              size_t msg_len);
int bn256_bls_verify(g2_t p, uint8_t *signature, uint8_t *msg, size_t msg_len);
void bn256_bls_sign_message(uint8_t *out_buf, uint8_t *msg, uint64_t msg_len, scalar_t secret_key);
void bn256_bls_keygen(g2_t pk, scalar_t sk);

#endif //BN256_BLS_H
