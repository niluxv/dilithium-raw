import json

def cfg_all(cfgs: list[str]) -> str:
    if len(cfgs) == 1:
        return "cfg({})".format(cfgs[0])
    else:
        return "cfg(all({}))".format(", ".join(cfgs))

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
            test_cfgs = ["test"]
            if impl == "avx2":
                test_cfgs.append("target_feature = \"avx2\"")

            template = f"""\
pub const PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES: usize = {publickey_bytes};
pub const PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES: usize = {secretkey_bytes};
pub const PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_BYTES: usize = {signature_bytes};
use cty::{{c_int, size_t}};

#[link(name = "dilithium{level}_{impl}")]
extern "C" {{
    /// Generate a new keypair, writing the public key to `pk` and the secret
    /// key to `sk`. Requires a buffer `random` to be filled with
    /// cryptographically secure random bytes, living at least until the
    /// function returns.
    pub fn PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_keypair(
        pk: *mut [u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES],
        sk: *mut [u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES],
        random: *mut [u8; 128],
    ) -> c_int;

    pub fn PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut size_t,
        m: *const u8,
        mlen: size_t,
        sk: *const [u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES],
    ) -> c_int;

    pub fn PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_verify(
        sig: *const u8,
        siglen: size_t,
        m: *const u8,
        mlen: size_t,
        pk: *const [u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES],
    ) -> c_int;
}}

#[{cfg_all(test_cfgs)}]
mod tests {{
    use super::*;

    #[test]
    fn test_sign_verify() {{
        let msg = b"hello world";

        let mut seckey = [0u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES];
        let mut pubkey = [0u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES];
        // not secure random, but deterministic and good enough for the test
        let mut random = [37u8; 128];
        let res = unsafe {{
            PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_keypair(
                &mut pubkey as *mut [u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES],
                &mut seckey as *mut [u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES],
                &mut random as *mut [u8; 128],
            )
        }};
        assert_eq!(res, 0);

        let mut sig = [9u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_BYTES];
        let mut len: usize = 0;
        let res = unsafe {{
            PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_signature(
                &mut sig as *mut u8,
                &mut len as *mut usize,
                msg as *const u8,
                msg.len(),
                &seckey as *const [u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES],
            )
        }};
        assert_eq!(res, 0);

        let res = unsafe {{
            PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_verify(
                &sig as *const u8,
                len,
                msg as *const u8,
                msg.len(),
                &pubkey as *const [u8; PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES],
            )
        }};
        assert_eq!(res, 0, "Invalid signature crated!");
    }}
}}
"""

            with open(f"src/ffi/dilithium{level}_{impl}.rs", 'w') as rust_file:
                rust_file.write(template)

if __name__ == "__main__":
    main()
