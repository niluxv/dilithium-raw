/* automatically generated by rust-bindgen 0.59.2 */

pub const PQCLEAN_DILITHIUM3_AARCH64_CRYPTO_PUBLICKEYBYTES: u32 = 1952;
pub const PQCLEAN_DILITHIUM3_AARCH64_CRYPTO_SECRETKEYBYTES: u32 = 4000;
pub const PQCLEAN_DILITHIUM3_AARCH64_CRYPTO_BYTES: u32 = 3293;
pub const PQCLEAN_DILITHIUM3_AARCH64_CRYPTO_ALGNAME: &[u8; 11usize] = b"Dilithium3\0";
pub type size_t = ::std::os::raw::c_ulong;
pub type __uint8_t = ::std::os::raw::c_uchar;
extern "C" {
    pub fn PQCLEAN_DILITHIUM3_AARCH64_crypto_sign_keypair(
        pk: *mut u8,
        sk: *mut u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn PQCLEAN_DILITHIUM3_AARCH64_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut size_t,
        m: *const u8,
        mlen: size_t,
        sk: *const u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn PQCLEAN_DILITHIUM3_AARCH64_crypto_sign_verify(
        sig: *const u8,
        siglen: size_t,
        m: *const u8,
        mlen: size_t,
        pk: *const u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn PQCLEAN_DILITHIUM3_AARCH64_crypto_sign(
        sm: *mut u8,
        smlen: *mut size_t,
        m: *const u8,
        mlen: size_t,
        sk: *const u8,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn PQCLEAN_DILITHIUM3_AARCH64_crypto_sign_open(
        m: *mut u8,
        mlen: *mut size_t,
        sm: *const u8,
        smlen: size_t,
        pk: *const u8,
    ) -> ::std::os::raw::c_int;
}
