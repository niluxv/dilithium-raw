#ifndef PQCLEAN_DILITHIUM3_CLEAN_SIGN_H
#define PQCLEAN_DILITHIUM3_CLEAN_SIGN_H
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include <stddef.h>
#include <stdint.h>

int PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk,
    uint8_t random[2 * SEEDBYTES + CRHBYTES]);

int PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *sk);

int PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

#endif
