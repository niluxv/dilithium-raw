//! Macro to generate rusty/non-ffi dilithium modules.

macro_rules! newtype_as_ref {
    ($new_ty:ty, $inner_ty:ty) => {
        impl core::convert::AsRef<$inner_ty> for $new_ty {
            fn as_ref(&self) -> &$inner_ty {
                &self.0
            }
        }
    };
}

macro_rules! newtype_from {
    ($new_ty:ty, $inner_ty:ty) => {
        impl core::convert::From<$inner_ty> for $new_ty {
            fn from(other: $inner_ty) -> Self {
                Self(other)
            }
        }
    };
}

pub(crate) use {newtype_as_ref, newtype_from};

macro_rules! impl_dilithium_module {
    ($regression_test_file:expr) => {
        /// Public key.
        ///
        /// Internally consists of a fixed length byte array.
        #[derive(Debug, PartialEq, Eq, Clone)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct PublicKey($crate::util::ByteArray<PUBLICKEYBYTES>);

        /// Secret key.
        ///
        /// Internally consists of a fixed length byte array.
        #[cfg_attr(test, derive(Debug, PartialEq))]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct SecretKey($crate::util::ByteArray<SECRETKEYBYTES>);

        /// Signature.
        #[derive(Debug, PartialEq, Eq, Clone)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct Signature($crate::util::ByteArray<SIGNATUREBYTES>);

        impl core::convert::AsRef<[u8]> for PublicKey {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        $crate::macros::newtype_as_ref!(PublicKey, $crate::util::ByteArray<PUBLICKEYBYTES>);
        $crate::macros::newtype_as_ref!(SecretKey, $crate::util::ByteArray<SECRETKEYBYTES>);
        $crate::macros::newtype_as_ref!(Signature, $crate::util::ByteArray<SIGNATUREBYTES>);
        $crate::macros::newtype_from!(PublicKey, $crate::util::ByteArray<PUBLICKEYBYTES>);
        $crate::macros::newtype_from!(SecretKey, $crate::util::ByteArray<SECRETKEYBYTES>);
        $crate::macros::newtype_from!(Signature, $crate::util::ByteArray<SIGNATUREBYTES>);

        // You never want to change a public key, right?
        #[cfg(any(test, feature = "hazmat"))]
        impl core::convert::AsMut<[u8]> for PublicKey {
            fn as_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }

        impl core::convert::AsRef<[u8]> for SecretKey {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        // You never want to change a secret key, right?
        #[cfg(any(test, feature = "hazmat"))]
        impl core::convert::AsMut<[u8]> for SecretKey {
            fn as_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }

        impl core::convert::AsRef<[u8]> for Signature {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        // You never want to change a signature, right?
        #[cfg(any(test, feature = "hazmat"))]
        impl core::convert::AsMut<[u8]> for Signature {
            fn as_mut(&mut self) -> &mut [u8] {
                self.0.as_mut()
            }
        }

        impl PublicKey {
            fn empty() -> Self {
                Self($crate::util::ByteArray::new([0; PUBLICKEYBYTES]))
            }
        }

        impl SecretKey {
            fn empty() -> Self {
                Self($crate::util::ByteArray::new([0; SECRETKEYBYTES]))
            }
        }

        impl Signature {
            fn empty() -> Self {
                Self($crate::util::ByteArray::new([0; SIGNATUREBYTES]))
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
                message: &[u8],
                sk: &[u8; SECRETKEYBYTES],
            ) -> c_int {
                #[cfg(enable_avx2)]
                {
                    if std::is_x86_feature_detected!("avx2") {
                        return unsafe { avx2::crypto_sign_signature(sig, message, sk) };
                    }
                }
                #[cfg(enable_aarch64)]
                {
                    return unsafe { aarch64::crypto_sign_signature(sig, message, sk) };
                }
                unsafe { clean::crypto_sign_signature(sig, message, sk) }
            }

            pub unsafe fn crypto_sign_verify(
                sig: &[u8; SIGNATUREBYTES],
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
        ///
        /// # Security
        /// The buffer `random` MUST be completely filled with cryptographically secure
        /// random bytes. Use a proper cryptographically secure random number generator
        /// for it (e.g. `rand::rngs::OsRng`)!
        pub fn generate_keypair(random: &mut [u8; 128]) -> (PublicKey, SecretKey) {
            let mut pk = PublicKey::empty();
            let mut sk = SecretKey::empty();
            // SAFETY: `pk`, `sk` and `random` buffers are valid for writes and live long
            // enough
            unsafe { detect_arch::crypto_sign_keypair(pk.0.as_mut(), sk.0.as_mut(), random) };
            (pk, sk)
        }

        /// Sign message `m` with secret key `sk`.
        pub fn sign<M: AsRef<[u8]>>(m: M, sk: &SecretKey) -> Signature {
            let mut sig = Signature::empty();
            let message: &[u8] = m.as_ref();

            unsafe { detect_arch::crypto_sign_signature(sig.0.as_mut(), message, sk.0.as_ref()) };

            sig
        }

        /// Verify signature `sig` for message `m` and public key `pk`.
        pub fn verify<M: AsRef<[u8]>>(
            m: M,
            sig: &Signature,
            pk: &PublicKey,
        ) -> crate::VerificationResult {
            let message: &[u8] = m.as_ref();

            let res =
                unsafe { detect_arch::crypto_sign_verify(sig.0.as_ref(), message, pk.0.as_ref()) };

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
            fn test_invalid_other_signature() {
                let msg = b"hello world";
                let mut random = [37u8; 128];

                let (pubkey, seckey) = generate_keypair(&mut random);
                let sig = sign(&msg.as_ref(), &seckey);

                let other_msg = b"hello warld";
                let res = verify(&other_msg.as_ref(), &sig, &pubkey);
                assert!(res.is_err(), "Invalid signature accepted!");
            }

            #[test]
            fn test_invalid_modified_signature() {
                let msg = b"hello world";
                let mut random = [37u8; 128];

                let (pubkey, seckey) = generate_keypair(&mut random);
                let mut sig = sign(&msg.as_ref(), &seckey);
                // modify signature
                sig.as_mut()[0] = 0;

                let res = verify(&msg.as_ref(), &sig, &pubkey);
                assert!(res.is_err(), "Invalid signature accepted!");
            }

            #[test]
            fn test_deterministic_keygen() {
                let mut random = [37u8; 128];
                let (pubkey1, seckey1) = generate_keypair(&mut random);
                // the seed is probably never modified in the C code, but it uses mutable
                // references for some reason
                assert_eq!(random, [37u8; 128]);
                let (pubkey2, seckey2) = generate_keypair(&mut random);
                assert_eq!(pubkey1, pubkey2);
                assert_eq!(seckey1, seckey2);
            }
        }

        #[cfg(all(test, feature = "serde"))]
        mod regression_test {
            use super::*;

            #[derive(serde::Serialize, serde::Deserialize)]
            struct RegressionTestExample {
                seed: crate::util::ByteArray<128>,
                pubkey: PublicKey,
                seckey: SecretKey,
                message: String,
                signature: Signature,
            }

            #[test]
            fn test_keygen_sign_verify_regression() {
                let ron_str = include_str!($regression_test_file);
                let regression_tests: Vec<RegressionTestExample> =
                    ron::de::from_str(ron_str).expect("could not deserialize regression test file");

                for example in regression_tests {
                    let mut seed = example.seed.clone();
                    let (pubkey, seckey) = generate_keypair(&mut seed.0);
                    // check seed is not changed
                    assert_eq!(seed, example.seed);
                    // check key generation determinism
                    assert_eq!(pubkey, example.pubkey);
                    assert_eq!(seckey, example.seckey);
                    // check signature determinism
                    let signature = sign(&example.message, &seckey);
                    assert_eq!(signature, example.signature);
                    // check verification success
                    assert!(verify(&example.message, &signature, &pubkey).is_ok());
                }
            }
        }
    };
}

pub(crate) use impl_dilithium_module;
