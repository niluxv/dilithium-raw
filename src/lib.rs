#![forbid(rust_2018_compatibility, unsafe_op_in_unsafe_fn)]
#![deny(future_incompatible, rust_2018_idioms)]
#![warn(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

pub mod ffi;

/// Message did verify correctly.
pub struct VerificationOk;
/// Message did not verify against the given signature.
pub struct VerificationFailure;

pub type VerificationResult = Result<VerificationOk, VerificationFailure>;

mod sanity {
    // We need this equality because in the build script we can only get the width
    // of a pointer, not that of a `usize`.
    const _: () = core::assert!(core::mem::size_of::<usize>() == core::mem::size_of::<*const u8>());
}

macro_rules! impl_dilithium_module {
    () => {
        pub struct PublicKey([u8; PUBLICKEYBYTES]);
        pub struct SecretKey([u8; SECRETKEYBYTES]);
        pub struct Signature([u8; SIGNATUREBYTES], usize);

        impl PublicKey {
            fn empty() -> Self {
                Self([0; PUBLICKEYBYTES])
            }
        }

        impl SecretKey {
            fn empty() -> Self {
                Self([0; SECRETKEYBYTES])
            }
        }

        mod detect_arch {
            use super::*;
            use cty::c_int;

            pub unsafe fn crypto_sign_keypair(
                pk: &mut [u8; PUBLICKEYBYTES],
                sk: &mut [u8; SECRETKEYBYTES],
                random: &mut [u8; 128],
            ) -> c_int {
                #[cfg(enable_avx2)]
                {
                    if std::is_x86_feature_detected!("avx2") {
                        return unsafe { avx2::crypto_sign_keypair(pk, sk, random) };
                    }
                }
                #[cfg(enable_aarch64)]
                {
                    return unsafe { aarch64::crypto_sign_keypair(pk, sk, random) };
                }
                unsafe { clean::crypto_sign_keypair(pk, sk, random) }
            }

            pub unsafe fn crypto_sign_signature(
                sig: &mut [u8; SIGNATUREBYTES],
                siglen: &mut usize,
                message: &[u8],
                sk: &[u8; SECRETKEYBYTES],
            ) -> c_int {
                #[cfg(enable_avx2)]
                {
                    if std::is_x86_feature_detected!("avx2") {
                        return unsafe { avx2::crypto_sign_signature(sig, siglen, message, sk) };
                    }
                }
                #[cfg(enable_aarch64)]
                {
                    return unsafe { aarch64::crypto_sign_signature(sig, siglen, message, sk) };
                }
                unsafe { clean::crypto_sign_signature(sig, siglen, message, sk) }
            }

            pub unsafe fn crypto_sign_verify(
                sig: &[u8],
                message: &[u8],
                pk: &[u8; PUBLICKEYBYTES],
            ) -> c_int {
                #[cfg(enable_avx2)]
                {
                    if std::is_x86_feature_detected!("avx2") {
                        return unsafe { avx2::crypto_sign_verify(sig, message, pk) };
                    }
                }
                #[cfg(enable_aarch64)]
                {
                    return unsafe { aarch64::crypto_sign_verify(sig, message, pk) };
                }
                unsafe { clean::crypto_sign_verify(sig, message, pk) }
            }
        }

        /// Generate a new keypair. Requires a buffer `random` to be filled with
        /// cryptographically secure random bytes.
        pub fn generate_keypair(random: &mut [u8; 128]) -> (PublicKey, SecretKey) {
            let mut pk = PublicKey::empty();
            let mut sk = SecretKey::empty();
            // SAFETY: `pk`, `sk` and `random` buffers are valid for writes and live long enough
            unsafe {
                detect_arch::crypto_sign_keypair(&mut pk.0, &mut sk.0, random)
            };
            (pk, sk)
        }

        /// Sign message.
        pub fn sign<M: AsRef<[u8]>>(m: M, sk: &SecretKey) -> Signature {
            let mut sigbuf = [0u8; SIGNATUREBYTES];
            let mut siglen: usize = 0;
            let message: &[u8] = m.as_ref();

            unsafe {
                detect_arch::crypto_sign_signature(
                    &mut sigbuf,
                    &mut siglen,
                    message,
                    &sk.0,
                )
            };

            Signature(sigbuf, siglen)
        }

        /// Verify signature.
        pub fn verify<M: AsRef<[u8]>>(m: M, sig: &Signature, pk: &PublicKey) -> crate::VerificationResult {
            let message: &[u8] = m.as_ref();

            let res = unsafe {
                detect_arch::crypto_sign_verify(
                    &sig.0[..sig.1],
                    message,
                    &pk.0,
                )
            };

            if res == 0 {
                Ok(crate::VerificationOk)
            } else {
                Err(crate::VerificationFailure)
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn test_sign_verify() {
                let msg = b"hello world";
                let mut random = [37u8; 128];

                let (pubkey, seckey) = generate_keypair(&mut random);
                let sig = sign(&msg.as_ref(), &seckey);

                let res = verify(&msg.as_ref(), &sig, &pubkey);
                assert!(res.is_ok(), "Invalid signature crated!");
            }

            #[test]
            fn test_invalid_signature() {
                let msg = b"hello world";
                let mut random = [37u8; 128];

                let (pubkey, seckey) = generate_keypair(&mut random);
                let sig = sign(&msg.as_ref(), &seckey);

                let other_msg = b"hello warld";
                let res = verify(&other_msg.as_ref(), &sig, &pubkey);
                assert!(res.is_err(), "Invalid signature accepted!");
            }
        }
    }
}

#[cfg(feature = "dilithium2")]
pub mod dilithium2 {
    use crate::ffi::dilithium2::*;
    impl_dilithium_module!();
}

#[cfg(feature = "dilithium3")]
pub mod dilithium3 {
    use crate::ffi::dilithium3::*;
    impl_dilithium_module!();
}

#[cfg(feature = "dilithium5")]
pub mod dilithium5 {
    use crate::ffi::dilithium5::*;
    impl_dilithium_module!();
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
