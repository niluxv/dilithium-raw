//! Dilithium 5 clean and aarch64 FFI and Rust porting.

use super::{DilithiumBasicParams, DilithiumTypes};
use crate::util::UninitArray;

pub const PUBLICKEYBYTES: usize = 2592;
pub const SECRETKEYBYTES: usize = 4864;
pub const SIGNATUREBYTES: usize = 4595;

super::prepare_dilithium_level!();

super::create_dilithium_instance!(Dilithium5Clean, doc = "Dilithium 5 clean implementation.");
super::impl_basic_functions!(Dilithium5Clean);
pub mod clean;

#[cfg(enable_aarch64)]
super::create_dilithium_instance!(
    Dilithium5Aarch64,
    doc = "Dilithium 5 aarch64 implementation."
);
#[cfg(enable_aarch64)]
super::impl_basic_functions!(Dilithium5Aarch64);
#[cfg(enable_aarch64)]
pub mod aarch64;
