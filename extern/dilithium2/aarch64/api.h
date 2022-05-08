#ifndef PQCLEAN_DILITHIUM2_AARCH64_API_H
#define PQCLEAN_DILITHIUM2_AARCH64_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_DILITHIUM2_AARCH64_CRYPTO_PUBLICKEYBYTES 1312
#define PQCLEAN_DILITHIUM2_AARCH64_CRYPTO_SECRETKEYBYTES 2528
#define PQCLEAN_DILITHIUM2_AARCH64_CRYPTO_BYTES 2420
#define PQCLEAN_DILITHIUM2_AARCH64_CRYPTO_ALGNAME "Dilithium2"

int PQCLEAN_DILITHIUM2_AARCH64_crypto_sign_keypair(
    uint8_t pk[PQCLEAN_DILITHIUM2_AARCH64_CRYPTO_PUBLICKEYBYTES],
    uint8_t sk[PQCLEAN_DILITHIUM2_AARCH64_CRYPTO_SECRETKEYBYTES],
    uint8_t random[128]
);

int PQCLEAN_DILITHIUM2_AARCH64_crypto_sign_signature(
    uint8_t* sig, size_t* siglen,
    const uint8_t* m, size_t mlen,
    const uint8_t sk[PQCLEAN_DILITHIUM2_AARCH64_CRYPTO_SECRETKEYBYTES]
);

int PQCLEAN_DILITHIUM2_AARCH64_crypto_sign_verify(
    const uint8_t* sig, size_t siglen,
    const uint8_t* m, size_t mlen,
    const uint8_t pk[PQCLEAN_DILITHIUM2_AARCH64_CRYPTO_PUBLICKEYBYTES]
);

#endif
