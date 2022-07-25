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

        rust = f"""\
pub const PUBLICKEYBYTES: usize = {publickey_bytes};
pub const SECRETKEYBYTES: usize = {secretkey_bytes};
pub const SIGNATUREBYTES: usize = {signature_bytes};
use cty::{{c_int, size_t}};
"""

        for impl in param_set["implementations"]:
            assert impl in ["clean", "avx2", "aarch64"]
            IMPL = impl.upper()
            cfgs = [f"feature = \"dilithium{level}\""]
            if impl == "avx2":
                cfgs.append("enable_avx2")
            elif impl == "aarch64":
                cfgs.append("enable_aarch64")
            test_cfgs = ["test"]
            if impl == "avx2":
                test_cfgs.append("target_feature = \"avx2\"")

            rust += f"""\

#[{cfg_all(cfgs)}]
pub mod {impl} {{
    use super::*;

    #[link(name = "dilithium{level}_{impl}")]
    extern "C" {{
        /// Generate a new keypair, writing the public key to `pk` and the secret
        /// key to `sk`. Requires a buffer `random` to be filled with
        /// cryptographically secure random bytes, living at least until the
        /// function returns.
        fn PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_keypair(
            pk: *mut [u8; PUBLICKEYBYTES],
            sk: *mut [u8; SECRETKEYBYTES],
            random: *mut [u8; 128],
        ) -> c_int;

        fn PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_signature(
            sig: *mut [u8; SIGNATUREBYTES],
            m: *const u8,
            mlen: size_t,
            sk: *const [u8; SECRETKEYBYTES],
        ) -> c_int;

        fn PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_verify(
            sig: *const [u8; SIGNATUREBYTES],
            m: *const u8,
            mlen: size_t,
            pk: *const [u8; PUBLICKEYBYTES],
        ) -> c_int;
    }}

    pub unsafe fn crypto_sign_keypair(
        pk: &mut [u8; PUBLICKEYBYTES],
        sk: &mut [u8; SECRETKEYBYTES],
        random: &mut [u8; 128],
    ) -> c_int {{
        unsafe {{
            PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_keypair(pk as *mut _, sk as *mut _, random as *mut _)
        }}
    }}

    pub unsafe fn crypto_sign_signature(
        sig: &mut [u8; SIGNATUREBYTES],
        message: &[u8],
        sk: &[u8; SECRETKEYBYTES],
    ) -> c_int {{
        unsafe {{
            PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_signature(
                sig as *mut _,
                message.as_ptr(),
                message.len(),
                sk as *const _,
            )
        }}
    }}

    pub unsafe fn crypto_sign_verify(
        sig: &[u8; SIGNATUREBYTES],
        message: &[u8],
        pk: &[u8; PUBLICKEYBYTES],
    ) -> c_int {{
        unsafe {{
            PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_verify(
                sig as *const _,
                message.as_ptr(),
                message.len(),
                pk as *const _,
            )
        }}
    }}

    #[{cfg_all(test_cfgs)}]
    mod tests {{
        use super::*;

        #[test]
        fn test_sign_verify() {{
            let msg = b"hello world";

            let mut seckey = [0u8; SECRETKEYBYTES];
            let mut pubkey = [0u8; PUBLICKEYBYTES];
            // not secure random, but deterministic and good enough for the test
            let mut random = [37u8; 128];
            let res = unsafe {{
                crypto_sign_keypair(
                    &mut pubkey,
                    &mut seckey,
                    &mut random,
                )
            }};
            assert_eq!(res, 0);

            let mut sig = [0u8; SIGNATUREBYTES];
            let res = unsafe {{
                crypto_sign_signature(
                    &mut sig,
                    &msg[..],
                    &seckey,
                )
            }};
            assert_eq!(res, 0);

            let res = unsafe {{
                crypto_sign_verify(
                    &sig,
                    &msg[..],
                    &pubkey,
                )
            }};
            assert_eq!(res, 0, "Invalid signature crated!");
        }}
    }}
}}
"""

        with open(f"src/ffi/dilithium{level}.rs", 'w') as rust_file:
            rust_file.write(rust)

if __name__ == "__main__":
    main()
