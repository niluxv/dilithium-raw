use super::{
    params, Poly, PolyVecK, PolyVecL, CRHBYTES, PUBLICKEYBYTES, SECRETKEYBYTES, SEEDBYTES,
    SIGNATUREBYTES,
};

mod ffi;
mod sign {
    use super::*;

    super::super::super::sign::sign_api!();
}
pub use sign::{crypto_sign_keypair, crypto_sign_signature, crypto_sign_verify};