pub const PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1312;
pub const PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 2528;
pub const PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES: usize = 2420;
use cty::{c_int, size_t};

#[link(name = "dilithium2_clean")]
extern "C" {
    /// Generate a new keypair, writing the public key to `pk` and the secret
    /// key to `sk`. Requires a buffer `random` to be filled with
    /// cryptographically secure random bytes, living at least until the
    /// function returns.
    pub fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
        random: *mut [u8; 128],
    ) -> c_int;

    pub fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut size_t,
        m: *const u8,
        mlen: size_t,
        sk: *const u8,
    ) -> c_int;

    pub fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
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

        let mut seckey = [0u8; PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_SECRETKEYBYTES];
        let mut pubkey = [0u8; PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES];
        // not secure random, but deterministic and good enough for the test
        let mut random = [37u8; 128];
        let res = unsafe {
            PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(
                &mut pubkey as *mut u8,
                &mut seckey as *mut u8,
                &mut random as *mut [u8; 128],
            )
        };
        assert_eq!(res, 0);

        let mut sig = [9u8; PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_BYTES];
        let mut len: usize = 0;
        let res = unsafe {
            PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
                &mut sig as *mut u8,
                &mut len as *mut usize,
                msg as *const u8,
                msg.len(),
                &seckey as *const u8,
            )
        };
        assert_eq!(res, 0);

        let res = unsafe {
            PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
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
