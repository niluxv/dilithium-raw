import json

def main():
    with open("scripts/dilithium.json", 'r') as json_file:
        spec = json.load(json_file)

    for param_set in spec["parameter_sets"]:
        level = param_set["security_level"]
        publickey_bytes = param_set["publickey_bytes"]
        secretkey_bytes = param_set["secretkey_bytes"]
        signature_bytes = param_set["signature_bytes"]
        impl = "avx2"
        IMPL = impl.upper()

        template = f"""\
#ifndef PQCLEAN_DILITHIUM{level}_{IMPL}_SIGN_H
#define PQCLEAN_DILITHIUM{level}_{IMPL}_SIGN_H
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include <stddef.h>
#include <stdint.h>

int PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_keypair(
    uint8_t pk[PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES],
    uint8_t sk[PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES],
    uint8_t random[2 * SEEDBYTES + CRHBYTES]
);

int PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_signature(
    uint8_t* sig,
    const uint8_t* m, size_t mlen,
    const uint8_t sk[PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES]
);

int PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_verify(
    const uint8_t* sig,
    const uint8_t* m, size_t mlen,
    const uint8_t pk[PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES]
);

#endif
"""

        with open(f"extern/dilithium{level}/{impl}/sign.h", 'w') as h_file:
            h_file.write(template)

if __name__ == "__main__":
    main()
