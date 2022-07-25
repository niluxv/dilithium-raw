#ifndef PQCLEAN_DILITHIUM2_AVX2_SIGN_H
#define PQCLEAN_DILITHIUM2_AVX2_SIGN_H
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include <stddef.h>
#include <stdint.h>

int PQCLEAN_DILITHIUM2_AVX2_crypto_sign_keypair(
    uint8_t pk[PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES],
    uint8_t sk[PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES],
    uint8_t random[2 * SEEDBYTES + CRHBYTES]
);

int PQCLEAN_DILITHIUM2_AVX2_crypto_sign_signature(
    uint8_t* sig,
    const uint8_t* m, size_t mlen,
    const uint8_t sk[PQCLEAN_DILITHIUM2_AVX2_CRYPTO_SECRETKEYBYTES]
);

int PQCLEAN_DILITHIUM2_AVX2_crypto_sign_verify(
    const uint8_t* sig,
    const uint8_t* m, size_t mlen,
    const uint8_t pk[PQCLEAN_DILITHIUM2_AVX2_CRYPTO_PUBLICKEYBYTES]
);

#endif
