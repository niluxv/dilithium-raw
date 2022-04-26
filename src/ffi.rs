#[cfg(feature = "dilithium2")]
pub mod dilithium2_clean;
#[cfg(feature = "dilithium3")]
pub mod dilithium3_clean;
#[cfg(feature = "dilithium5")]
pub mod dilithium5_clean;
#[cfg(all(feature = "dilithium2", target_arch = "x86_64", target_feature = "avx2"))]
pub mod dilithium2_avx2;
#[cfg(all(feature = "dilithium3", target_arch = "x86_64", target_feature = "avx2"))]
pub mod dilithium3_avx2;
#[cfg(all(feature = "dilithium5", target_arch = "x86_64", target_feature = "avx2"))]
pub mod dilithium5_avx2;
#[cfg(all(feature = "dilithium2", target_arch = "aarch64"))]
pub mod dilithium2_aarch;
#[cfg(all(feature = "dilithium3", target_arch = "aarch64"))]
pub mod dilithium3_aarch;
#[cfg(all(feature = "dilithium5", target_arch = "aarch64"))]
pub mod dilithium5_aarch;
