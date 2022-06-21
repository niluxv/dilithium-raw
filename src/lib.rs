#![no_std]
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
