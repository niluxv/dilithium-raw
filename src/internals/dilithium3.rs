//! Dilithium 3 clean and aarch64 FFI and Rust porting.

pub const PUBLICKEYBYTES: usize = 1952;
pub const SECRETKEYBYTES: usize = 4000;
pub const SIGNATUREBYTES: usize = 3293;

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
