def cfg_all(cfgs: list[str]) -> str:
    if len(cfgs) == 1:
        return "cfg({})".format(cfgs[0])
    else:
        return "cfg(all({}))".format(", ".join(cfgs))

for level in [2, 3, 5]:
    if level == 2:
        publickey_bytes = 1312
        secretkey_bytes = 2528
        signature_bytes = 2420
    elif level == 3:
        publickey_bytes = 1952
        secretkey_bytes = 4000
        signature_bytes = 3293
    elif level == 5:
        publickey_bytes = 2592
        secretkey_bytes = 4864
        signature_bytes = 4595

    for impl in ["clean", "avx2", "aarch64"]:
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
    pub fn PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

    pub fn PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut size_t,
        m: *const u8,
        mlen: size_t,
        sk: *const u8,
    ) -> c_int;

    pub fn PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_verify(
        sig: *const u8,
        siglen: size_t,
        m: *const u8,
        mlen: size_t,
        pk: *const u8,
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
        let res = unsafe {{
            PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_keypair(
                &mut pubkey as *mut u8,
                &mut seckey as *mut u8,
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
                &seckey as *const u8,
            )
        }};
        assert_eq!(res, 0);

        let res = unsafe {{
            PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_verify(
                &sig as *const u8,
                len,
                msg as *const u8,
                msg.len(),
                &pubkey as *const u8,
            )
        }};
        assert_eq!(res, 0, "Invalid signature crated!");
    }}
}}
"""

        with open(f"src/ffi/dilithium{level}_{impl}.rs", 'w') as f:
            f.write(template)
