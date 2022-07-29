//! Low level library for post-quantum signature scheme dilithium.
//!
//! Uses a slightly modified version of the C code of [`pqclean`] as the actual
//! implementation, which is compiled by a build script. The API is modified to
//! put the user in control of required randomness.
//!
//! The library has a minimal set of dependencies: in the default configuration
//! (without [`serde`] support) only [`cty`].
//!
//! # Security
//! __Warning__: This crate is intended as a lower level crate implementing a
//! primitive and exposing "not hard to misuse" APIs to provide the user with
//! maximum control. Only use if you know what you are doing! Always read
//! security sections in the documentation. Otherwise use a higher level
//! wrapper.
//!
//! __Warning__: This crate has not been audited for correctness. The C code is
//! copied from the well-regarded [`pqclean`] project, but since then
//! modifications have been made.
//!
//! USE AT YOUR OWN RISK!
//!
//! # Usage
//! The API is located in the `dilithiumX` module, for X in {2, 3, 5}. To
//! generate a keypair, use `generate_keypair`. Note: it requires a buffer
//! filled with cryptographically secure random bytes. The random buffer is not
//! modified, so zeroization is left to the user. Example:
//! ```
//! use dilithium_raw::dilithium5::generate_keypair;
//! use rand::rngs::OsRng;
//! use rand::Rng;
//! use zeroize::Zeroize;
//!
//! // fill buffer of 128 bytes with secure random data
//! let mut random = [0; 128];
//! OsRng.fill(&mut random[..]);
//!
//! // generate keypair
//! let (pubkey, seckey) = generate_keypair(&mut random);
//!
//! // zeroize the buffer with random data
//! random.zeroize();
//! ```
//!
//! To sign a message using the secret key, use `sign` and to verify it using
//! the public key, use `verify`. `verify` returns `Ok` for a valid signature
//! and `Err` for an invalid signature. Example:
//! ```
//! use dilithium_raw::dilithium5::{sign, verify};
//!
//! // snip, get a `pubkey` and `seckey` with the public and secret key respectively
//! # use rand::Rng;
//! # let mut random = [0; 128];
//! # rand::rngs::OsRng.fill(&mut random[..]);
//! # let (pubkey, seckey) = dilithium_raw::dilithium5::generate_keypair(&mut random);
//!
//! let msg = "hello world";
//! let sig = sign(msg, &seckey);
//! assert!(verify(msg, &sig, &pubkey).is_ok());
//! ```
//!
//! [`cty`]: https://crates.io/crates/cty
//! [`pqclean`]: https://github.com/PQClean/PQClean
//! [`serde`]: https://crates.io/crates/serde

#![forbid(rust_2018_compatibility, unsafe_op_in_unsafe_fn)]
#![deny(future_incompatible, rust_2018_idioms)]
#![warn(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

/// Low level C bindings.
pub mod ffi;
mod internals;
/// Utilities, mostly for use in this crate.
pub mod util;

/// Message did verify correctly.
pub struct VerificationOk;
/// Message did not verify against the given signature.
pub struct VerificationFailure;

/// Type alias for the return type of verification checks.
pub type VerificationResult = Result<VerificationOk, VerificationFailure>;

mod sanity {
    // We need this equality because in the build script we can only get the width
    // of a pointer, not that of a `usize`.
    const _: () = core::assert!(core::mem::size_of::<usize>() == core::mem::size_of::<*const u8>());
}

mod macros;

/// Module containing a mid-level API to dilithium 2.
#[cfg(feature = "dilithium2")]
pub mod dilithium2 {
    use crate::ffi::dilithium2::*;
    crate::macros::impl_dilithium_module!("regression_tests/dilithium2.ron");
}

/// Module containing a mid-level API to dilithium 3.
#[cfg(feature = "dilithium3")]
pub mod dilithium3 {
    use crate::ffi::dilithium3::*;
    crate::macros::impl_dilithium_module!("regression_tests/dilithium3.ron");
}

/// Module containing a mid-level API to dilithium 5.
#[cfg(feature = "dilithium5")]
pub mod dilithium5 {
    use crate::ffi::dilithium5::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNATUREBYTES};
    mod clean {
        pub(crate) use crate::internals::dilithium5::*;
    }
    #[cfg(all(enable_avx2))]
    mod avx2 {
        pub(crate) use crate::ffi::dilithium5::avx2::*;
    }
    #[cfg(all(enable_aarch64))]
    mod avx2 {
        pub(crate) use crate::ffi::dilithium5::aarch64::*;
    }
    crate::macros::impl_dilithium_module!("regression_tests/dilithium5.ron");
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
