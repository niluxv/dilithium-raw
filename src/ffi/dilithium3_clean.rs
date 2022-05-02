pub const PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1952;
pub const PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 4000;
pub const PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES: usize = 3293;
use cty::{c_int, size_t};

#[link(name = "dilithium3_clean")]
extern "C" {
    pub fn PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> c_int;

    pub fn PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut size_t,
        m: *const u8,
        mlen: size_t,
        sk: *const u8,
    ) -> c_int;

    pub fn PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: size_t,
        m: *const u8,
        mlen: size_t,
        pk: *const u8,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let msg = b"hello world";

        let mut seckey = [0u8; PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES];
        let mut pubkey = [0u8; PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES];
        let res = unsafe {
            PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(
                &mut pubkey as *mut u8,
                &mut seckey as *mut u8,
            )
        };
        assert_eq!(res, 0);

        let mut sig = [9u8; PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES];
        let mut len: usize = 0;
        let res = unsafe {
            PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(
                &mut sig as *mut u8,
                &mut len as *mut usize,
                msg as *const u8,
                msg.len(),
                &seckey as *const u8,
            )
        };
        assert_eq!(res, 0);

        let res = unsafe {
            PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify(
                &sig as *const u8,
                len,
                msg as *const u8,
                msg.len(),
                &pubkey as *const u8,
            )
        };
        assert_eq!(res, 0, "Invalid signature crated!");
    }
}
