pub const PUBLICKEYBYTES: usize = 1312;
pub const SECRETKEYBYTES: usize = 2528;
pub const SIGNATUREBYTES: usize = 2420;
use cty::{c_int, size_t};

#[cfg(feature = "dilithium2")]
pub mod clean {
    use super::*;

    #[link(name = "dilithium2_clean")]
    extern "C" {
        /// Generate a new keypair, writing the public key to `pk` and the secret
        /// key to `sk`. Requires a buffer `random` to be filled with
        /// cryptographically secure random bytes, living at least until the
        /// function returns.
        fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(
            pk: *mut [u8; PUBLICKEYBYTES],
            sk: *mut [u8; SECRETKEYBYTES],
            random: *mut [u8; 128],
        ) -> c_int;

        fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
            sig: *mut u8,
            siglen: *mut size_t,
            m: *const u8,
            mlen: size_t,
            sk: *const [u8; SECRETKEYBYTES],
        ) -> c_int;

        fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
            sig: *const u8,
            siglen: size_t,
            m: *const u8,
            mlen: size_t,
            pk: *const [u8; PUBLICKEYBYTES],
        ) -> c_int;
    }

    pub unsafe fn crypto_sign_keypair(
        pk: &mut [u8; PUBLICKEYBYTES],
        sk: &mut [u8; SECRETKEYBYTES],
        random: &mut [u8; 128],
    ) -> c_int {
        unsafe {
            PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk as *mut _, sk as *mut _, random as *mut _)
        }
    }

    pub unsafe fn crypto_sign_signature(
        sig: &mut [u8; SIGNATUREBYTES],
        siglen: &mut usize,
        message: &[u8],
        sk: &[u8; SECRETKEYBYTES],
    ) -> c_int {
        unsafe {
            PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
                sig as *mut u8,
                siglen as *mut usize,
                message.as_ptr(),
                message.len(),
                sk as *const _,
            )
        }
    }

    pub unsafe fn crypto_sign_verify(
        sig: &[u8],
        message: &[u8],
        pk: &[u8; PUBLICKEYBYTES],
    ) -> c_int {
        unsafe {
            PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
                sig.as_ptr(),
                sig.len(),
                message.as_ptr(),
                message.len(),
                pk as *const _,
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_sign_verify() {
            let msg = b"hello world";

            let mut seckey = [0u8; SECRETKEYBYTES];
            let mut pubkey = [0u8; PUBLICKEYBYTES];
            // not secure random, but deterministic and good enough for the test
            let mut random = [37u8; 128];
            let res = unsafe {
                crypto_sign_keypair(
                    &mut pubkey,
                    &mut seckey,
                    &mut random,
                )
            };
            assert_eq!(res, 0);

            let mut sig = [0u8; SIGNATUREBYTES];
            let mut len: usize = 0;
            let res = unsafe {
                crypto_sign_signature(
                    &mut sig,
                    &mut len,
                    &msg[..],
                    &seckey,
                )
            };
            assert_eq!(res, 0);

            let res = unsafe {
                crypto_sign_verify(
                    &sig[..len],
                    &msg[..],
                    &pubkey,
                )
            };
            assert_eq!(res, 0, "Invalid signature crated!");
        }
    }
}

#[cfg(all(feature = "dilithium2", enable_avx2))]
pub mod avx2 {
    use super::*;

    #[link(name = "dilithium2_avx2")]
    extern "C" {
        /// Generate a new keypair, writing the public key to `pk` and the secret
        /// key to `sk`. Requires a buffer `random` to be filled with
        /// cryptographically secure random bytes, living at least until the
        /// function returns.
        fn PQCLEAN_DILITHIUM2_AVX2_crypto_sign_keypair(
            pk: *mut [u8; PUBLICKEYBYTES],
            sk: *mut [u8; SECRETKEYBYTES],
            random: *mut [u8; 128],
        ) -> c_int;

        fn PQCLEAN_DILITHIUM2_AVX2_crypto_sign_signature(
            sig: *mut u8,
            siglen: *mut size_t,
            m: *const u8,
            mlen: size_t,
            sk: *const [u8; SECRETKEYBYTES],
        ) -> c_int;

        fn PQCLEAN_DILITHIUM2_AVX2_crypto_sign_verify(
            sig: *const u8,
            siglen: size_t,
            m: *const u8,
            mlen: size_t,
            pk: *const [u8; PUBLICKEYBYTES],
        ) -> c_int;
    }

    pub unsafe fn crypto_sign_keypair(
        pk: &mut [u8; PUBLICKEYBYTES],
        sk: &mut [u8; SECRETKEYBYTES],
        random: &mut [u8; 128],
    ) -> c_int {
        unsafe {
            PQCLEAN_DILITHIUM2_AVX2_crypto_sign_keypair(pk as *mut _, sk as *mut _, random as *mut _)
        }
    }

    pub unsafe fn crypto_sign_signature(
        sig: &mut [u8; SIGNATUREBYTES],
        siglen: &mut usize,
        message: &[u8],
        sk: &[u8; SECRETKEYBYTES],
    ) -> c_int {
        unsafe {
            PQCLEAN_DILITHIUM2_AVX2_crypto_sign_signature(
                sig as *mut u8,
                siglen as *mut usize,
                message.as_ptr(),
                message.len(),
                sk as *const _,
            )
        }
    }

    pub unsafe fn crypto_sign_verify(
        sig: &[u8],
        message: &[u8],
        pk: &[u8; PUBLICKEYBYTES],
    ) -> c_int {
        unsafe {
            PQCLEAN_DILITHIUM2_AVX2_crypto_sign_verify(
                sig.as_ptr(),
                sig.len(),
                message.as_ptr(),
                message.len(),
                pk as *const _,
            )
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
            let res = unsafe {
                crypto_sign_keypair(
                    &mut pubkey,
                    &mut seckey,
                    &mut random,
                )
            };
            assert_eq!(res, 0);

            let mut sig = [0u8; SIGNATUREBYTES];
            let mut len: usize = 0;
            let res = unsafe {
                crypto_sign_signature(
                    &mut sig,
                    &mut len,
                    &msg[..],
                    &seckey,
                )
            };
            assert_eq!(res, 0);

            let res = unsafe {
                crypto_sign_verify(
                    &sig[..len],
                    &msg[..],
                    &pubkey,
                )
            };
            assert_eq!(res, 0, "Invalid signature crated!");
        }
    }
}

#[cfg(all(feature = "dilithium2", enable_aarch64))]
pub mod aarch64 {
    use super::*;

    #[link(name = "dilithium2_aarch64")]
    extern "C" {
        /// Generate a new keypair, writing the public key to `pk` and the secret
        /// key to `sk`. Requires a buffer `random` to be filled with
        /// cryptographically secure random bytes, living at least until the
        /// function returns.
        fn PQCLEAN_DILITHIUM2_AARCH64_crypto_sign_keypair(
            pk: *mut [u8; PUBLICKEYBYTES],
            sk: *mut [u8; SECRETKEYBYTES],
            random: *mut [u8; 128],
        ) -> c_int;

        fn PQCLEAN_DILITHIUM2_AARCH64_crypto_sign_signature(
            sig: *mut u8,
            siglen: *mut size_t,
            m: *const u8,
            mlen: size_t,
            sk: *const [u8; SECRETKEYBYTES],
        ) -> c_int;

        fn PQCLEAN_DILITHIUM2_AARCH64_crypto_sign_verify(
            sig: *const u8,
            siglen: size_t,
            m: *const u8,
            mlen: size_t,
            pk: *const [u8; PUBLICKEYBYTES],
        ) -> c_int;
    }

    pub unsafe fn crypto_sign_keypair(
        pk: &mut [u8; PUBLICKEYBYTES],
        sk: &mut [u8; SECRETKEYBYTES],
        random: &mut [u8; 128],
    ) -> c_int {
        unsafe {
            PQCLEAN_DILITHIUM2_AARCH64_crypto_sign_keypair(pk as *mut _, sk as *mut _, random as *mut _)
        }
    }

    pub unsafe fn crypto_sign_signature(
        sig: &mut [u8; SIGNATUREBYTES],
        siglen: &mut usize,
        message: &[u8],
        sk: &[u8; SECRETKEYBYTES],
    ) -> c_int {
        unsafe {
            PQCLEAN_DILITHIUM2_AARCH64_crypto_sign_signature(
                sig as *mut u8,
                siglen as *mut usize,
                message.as_ptr(),
                message.len(),
                sk as *const _,
            )
        }
    }

    pub unsafe fn crypto_sign_verify(
        sig: &[u8],
        message: &[u8],
        pk: &[u8; PUBLICKEYBYTES],
    ) -> c_int {
        unsafe {
            PQCLEAN_DILITHIUM2_AARCH64_crypto_sign_verify(
                sig.as_ptr(),
                sig.len(),
                message.as_ptr(),
                message.len(),
                pk as *const _,
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_sign_verify() {
            let msg = b"hello world";

            let mut seckey = [0u8; SECRETKEYBYTES];
            let mut pubkey = [0u8; PUBLICKEYBYTES];
            // not secure random, but deterministic and good enough for the test
            let mut random = [37u8; 128];
            let res = unsafe {
                crypto_sign_keypair(
                    &mut pubkey,
                    &mut seckey,
                    &mut random,
                )
            };
            assert_eq!(res, 0);

            let mut sig = [0u8; SIGNATUREBYTES];
            let mut len: usize = 0;
            let res = unsafe {
                crypto_sign_signature(
                    &mut sig,
                    &mut len,
                    &msg[..],
                    &seckey,
                )
            };
            assert_eq!(res, 0);

            let res = unsafe {
                crypto_sign_verify(
                    &sig[..len],
                    &msg[..],
                    &pubkey,
                )
            };
            assert_eq!(res, 0, "Invalid signature crated!");
        }
    }
}
