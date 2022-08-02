//! Dilithium 2 clean and aarch64 FFI and Rust porting.

use super::{DilithiumBasicParams, DilithiumTypes};
use crate::util::UninitArray;

pub const PUBLICKEYBYTES: usize = 1312;
pub const SECRETKEYBYTES: usize = 2528;
pub const SIGNATUREBYTES: usize = 2420;

super::prepare_dilithium_level!();

super::create_dilithium_instance!(Dilithium2Clean, doc = "Dilithium 2 clean implementation.");
super::impl_basic_functions!(Dilithium2Clean);
pub mod clean;

#[cfg(enable_aarch64)]
super::create_dilithium_instance!(
    Dilithium2Aarch64,
    doc = "Dilithium 2 aarch64 implementation."
);
#[cfg(enable_aarch64)]
super::impl_basic_functions!(Dilithium2Aarch64);
#[cfg(enable_aarch64)]
pub mod aarch64;
