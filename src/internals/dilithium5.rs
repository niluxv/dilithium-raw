//! Dilithium 5 clean and aarch64 FFI and Rust porting.

pub const PUBLICKEYBYTES: usize = 2592;
pub const SECRETKEYBYTES: usize = 4864;
pub const SIGNATUREBYTES: usize = 4595;

const SEEDBYTES: usize = 32;
const CRHBYTES: usize = 64;

mod params;

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

#[cfg(enable_aarch64)]
pub mod aarch64;
pub mod clean;