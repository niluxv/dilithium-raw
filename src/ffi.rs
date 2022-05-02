#[cfg(feature = "dilithium2")]
pub mod dilithium2_clean;
#[cfg(feature = "dilithium3")]
pub mod dilithium3_clean;
#[cfg(feature = "dilithium5")]
pub mod dilithium5_clean;
#[cfg(all(feature = "dilithium2", enable_avx2))]
pub mod dilithium2_avx2;
#[cfg(all(feature = "dilithium3", enable_avx2))]
pub mod dilithium3_avx2;
#[cfg(all(feature = "dilithium5", enable_avx2))]
pub mod dilithium5_avx2;
#[cfg(all(feature = "dilithium2", enable_aarch64))]
pub mod dilithium2_aarch64;
#[cfg(all(feature = "dilithium3", enable_aarch64))]
pub mod dilithium3_aarch64;
#[cfg(all(feature = "dilithium5", enable_aarch64))]
pub mod dilithium5_aarch64;
