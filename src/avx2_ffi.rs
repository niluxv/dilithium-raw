//! Low level C bindings to the avx2 implementation.

#[cfg(feature = "dilithium2")]
pub mod dilithium2;
#[cfg(feature = "dilithium3")]
pub mod dilithium3;
#[cfg(feature = "dilithium5")]
pub mod dilithium5;
