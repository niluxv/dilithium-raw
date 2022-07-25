import json

def main():
    with open("scripts/dilithium.json", 'r') as json_file:
        spec = json.load(json_file)

    for param_set in spec["parameter_sets"]:
        level = param_set["security_level"]
        publickey_bytes = param_set["publickey_bytes"]
        secretkey_bytes = param_set["secretkey_bytes"]
        signature_bytes = param_set["signature_bytes"]
        for impl in param_set["implementations"]:
            assert impl in ["clean", "avx2", "aarch64"]
            IMPL = impl.upper()

            template = f"""\
#ifndef PQCLEAN_DILITHIUM{level}_{IMPL}_API_H
#define PQCLEAN_DILITHIUM{level}_{IMPL}_API_H

#include <stddef.h>
#include <stdint.h>

#define PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES {publickey_bytes}
#define PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES {secretkey_bytes}
#define PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_BYTES {signature_bytes}
#define PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_ALGNAME "Dilithium{level}"

int PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_keypair(
    uint8_t pk[PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES],
    uint8_t sk[PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES],
    uint8_t random[128]
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

            with open(f"extern/dilithium{level}/{impl}/api.h", 'w') as h_file:
                h_file.write(template)

if __name__ == "__main__":
    main()
