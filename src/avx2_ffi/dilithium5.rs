pub const PUBLICKEYBYTES: usize = 2592;
pub const SECRETKEYBYTES: usize = 4864;
pub const SIGNATUREBYTES: usize = 4595;
use super::*;
use cty::{c_int, size_t};

#[link(name = "dilithium5_avx2")]
extern "C" {
    /// Generate a new keypair, writing the public key to `pk` and the secret
    /// key to `sk`. Requires a buffer `random` to be filled with
    /// cryptographically secure random bytes, living at least until the
    /// function returns.
    fn PQCLEAN_DILITHIUM5_AVX2_crypto_sign_keypair(
        pk: *mut [u8; PUBLICKEYBYTES],
        sk: *mut [u8; SECRETKEYBYTES],
        random: *mut [u8; 128],
    ) -> c_int;

    fn PQCLEAN_DILITHIUM5_AVX2_crypto_sign_signature(
        sig: *mut [u8; SIGNATUREBYTES],
        m: *const u8,
        mlen: size_t,
        sk: *const [u8; SECRETKEYBYTES],
    ) -> c_int;

    fn PQCLEAN_DILITHIUM5_AVX2_crypto_sign_verify(
        sig: *const [u8; SIGNATUREBYTES],
        m: *const u8,
        mlen: size_t,
        pk: *const [u8; PUBLICKEYBYTES],
    ) -> c_int;
}

pub unsafe fn crypto_sign_keypair(
    pk: &mut [u8; PUBLICKEYBYTES],
    sk: &mut [u8; SECRETKEYBYTES],
    random: &mut [u8; 128],
) {
    unsafe {
        PQCLEAN_DILITHIUM5_AVX2_crypto_sign_keypair(pk as *mut _, sk as *mut _, random as *mut _)
    };
}

pub unsafe fn crypto_sign_signature(
    sig: &mut [u8; SIGNATUREBYTES],
    message: &[u8],
    sk: &[u8; SECRETKEYBYTES],
) {
    unsafe {
        PQCLEAN_DILITHIUM5_AVX2_crypto_sign_signature(
            sig as *mut _,
            message.as_ptr(),
            message.len(),
            sk as *const _,
        )
    };
}

pub unsafe fn crypto_sign_verify(
    sig: &[u8; SIGNATUREBYTES],
    message: &[u8],
    pk: &[u8; PUBLICKEYBYTES],
) -> crate::VerificationResult {
    let res = unsafe {
        PQCLEAN_DILITHIUM5_AVX2_crypto_sign_verify(
            sig as *const _,
            message.as_ptr(),
            message.len(),
            pk as *const _,
        )
    };
    if res == 0 {
        Ok(crate::VerificationOk)
    } else {
        Err(crate::VerificationFailure)
    }
}

#[cfg(all(test, target_feature = "avx2"))]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let msg = b"hello world";

        let mut seckey = [0u8; SECRETKEYBYTES];
        let mut pubkey = [0u8; PUBLICKEYBYTES];
        // not secure random, but deterministic and good enough for the test
        let mut random = [37u8; 128];
        unsafe { crypto_sign_keypair(&mut pubkey, &mut seckey, &mut random) };

        let mut sig = [0u8; SIGNATUREBYTES];
        unsafe { crypto_sign_signature(&mut sig, &msg[..], &seckey) };

        let res = unsafe { crypto_sign_verify(&sig, &msg[..], &pubkey) };
        assert!(res.is_ok(), "Invalid signature crated!");
    }
}
