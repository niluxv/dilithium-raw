//! Dilithium 5 clean FFI and Rust porting.

pub const PUBLICKEYBYTES: usize = 2592;
pub const SECRETKEYBYTES: usize = 4864;
pub const SIGNATUREBYTES: usize = 4595;

const SEEDBYTES: usize = 32;
const CRHBYTES: usize = 64;

// Parameters for dilithium 5.
mod params {
    pub const N: usize = 256;
    pub const Q: usize = 8380417;

    pub const K: usize = 8;
    pub const L: usize = 7;
    pub const BETA: usize = 120;
    pub const GAMMA1: usize = 1 << 19;
    pub const GAMMA2: usize = (Q - 1) / 32;
    pub const OMEGA: usize = 75;

    pub const POLYW1_PACKEDBYTES: usize = 128;
}

/// Polynomial, represented by it's coefficients.
///
/// Corresponds to the `poly` C type.
#[derive(Clone)]
#[repr(C)]
pub struct Poly {
    coeffs: [i32; params::N],
}

/// Array of [`params::K`] polynomials.
///
/// Corresponds to the `polyveck` C type.
#[derive(Clone)]
#[repr(C)]
pub struct PolyVecK {
    vec: [Poly; params::K],
}

/// Array of [`params::L`] polynomials.
///
/// Corresponds to the `polyvecl` C type.
#[derive(Clone)]
#[repr(C)]
pub struct PolyVecL {
    vec: [Poly; params::L],
}

mod ffi;
mod sign;
pub use sign::{crypto_sign_keypair, crypto_sign_signature, crypto_sign_verify};
