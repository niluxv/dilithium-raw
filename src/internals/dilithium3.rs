//! Dilithium 3 clean and aarch64 FFI and Rust porting.

use super::{DilithiumBasicParams, DilithiumTypes};
use crate::util::UninitArray;

pub const PUBLICKEYBYTES: usize = 1952;
pub const SECRETKEYBYTES: usize = 4000;
pub const SIGNATUREBYTES: usize = 3293;

super::prepare_dilithium_level!();

super::create_dilithium_instance!(Dilithium3Clean, doc = "Dilithium 3 clean implementation.");
super::impl_basic_functions!(Dilithium3Clean);
pub mod clean;

#[cfg(enable_aarch64)]
super::create_dilithium_instance!(
    Dilithium3Aarch64,
    doc = "Dilithium 3 aarch64 implementation."
);
#[cfg(enable_aarch64)]
super::impl_basic_functions!(Dilithium3Aarch64);
#[cfg(enable_aarch64)]
pub mod aarch64;
