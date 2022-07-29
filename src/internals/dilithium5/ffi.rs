use super::*;
use core::mem::MaybeUninit;
use cty::c_int;

#[link(name = "dilithium5_clean")]
extern "C" {
    fn PQCLEAN_DILITHIUM5_CLEAN_polyvec_matrix_expand(
        mat: *mut [PolyVecL; params::K],
        rho: *const [u8; SEEDBYTES],
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyvecl_uniform_eta(
        v: *mut PolyVecL,
        seed: *const [u8; CRHBYTES],
        nonce: u16,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_uniform_eta(
        v: *mut PolyVecK,
        seed: *const [u8; CRHBYTES],
        nonce: u16,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyvecl_ntt(v: *mut PolyVecL);
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_reduce(v: *mut PolyVecK);
    fn PQCLEAN_DILITHIUM5_CLEAN_polyvecl_reduce(v: *mut PolyVecL);
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_invntt_tomont(v: *mut PolyVecK);
    fn PQCLEAN_DILITHIUM5_CLEAN_polyvecl_invntt_tomont(v: *mut PolyVecL);
    fn PQCLEAN_DILITHIUM5_CLEAN_polyvec_matrix_pointwise_montgomery(
        t: *mut PolyVecK,
        mat: *const [PolyVecL; params::K],
        v: *const PolyVecL,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_caddq(t: *mut PolyVecK);
    fn PQCLEAN_DILITHIUM5_CLEAN_pack_pk(
        pk: *mut [u8; PUBLICKEYBYTES],
        rho: *const [u8; SEEDBYTES],
        t1: *const PolyVecK,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_pack_sig(
        sig: *mut [u8; SIGNATUREBYTES],
        c: *const [u8; SEEDBYTES],
        z: *const PolyVecL,
        h: *const PolyVecK,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_pack_sk(
        sk: *mut [u8; SECRETKEYBYTES],
        rho: *const [u8; SEEDBYTES],
        tr: *const [u8; SEEDBYTES],
        key: *const [u8; SEEDBYTES],
        t0: *const PolyVecK,
        s1: *const PolyVecL,
        s2: *const PolyVecK,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_unpack_pk(
        rho: *mut [u8; SEEDBYTES],
        t1: *mut PolyVecK,
        pk: *const [u8; PUBLICKEYBYTES],
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_unpack_sig(
        c: *mut [u8; SEEDBYTES],
        z: *mut PolyVecL,
        h: *mut PolyVecK,
        sig: *const [u8; SIGNATUREBYTES],
    ) -> c_int;
    fn PQCLEAN_DILITHIUM5_CLEAN_unpack_sk(
        rho: *mut [u8; SEEDBYTES],
        tr: *mut [u8; SEEDBYTES],
        key: *mut [u8; SEEDBYTES],
        t0: *mut PolyVecK,
        s1: *mut PolyVecL,
        s2: *mut PolyVecK,
        sk: *const [u8; SECRETKEYBYTES],
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyvecl_chknorm(v: *const PolyVecL, bound: i32) -> c_int;
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_chknorm(v: *const PolyVecK, bound: i32) -> c_int;
    fn PQCLEAN_DILITHIUM5_CLEAN_poly_challenge(c: *mut Poly, seed: *const [u8; SEEDBYTES]);
    fn PQCLEAN_DILITHIUM5_CLEAN_poly_ntt(a: *mut Poly);
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_shiftl(v: *mut PolyVecK);
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_ntt(v: *mut PolyVecK);
    fn PQCLEAN_DILITHIUM5_CLEAN_polyvecl_pointwise_poly_montgomery(
        r: *mut PolyVecL,
        a: *const Poly,
        v: *const PolyVecL,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_add(
        w: *mut PolyVecK,
        u: *const PolyVecK,
        v: *const PolyVecK,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyvecl_add(
        w: *mut PolyVecL,
        u: *const PolyVecL,
        v: *const PolyVecL,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_sub(
        w: *mut PolyVecK,
        u: *const PolyVecK,
        v: *const PolyVecK,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_power2round(
        v1: *mut PolyVecK,
        v0: *mut PolyVecK,
        v: *const PolyVecK,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_use_hint(
        w: *mut PolyVecK,
        u: *const PolyVecK,
        h: *const PolyVecK,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyvecl_uniform_gamma1(
        v: *mut PolyVecL,
        seed: *const [u8; CRHBYTES],
        nonce: u16,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_decompose(
        v1: *mut PolyVecK,
        v0: *mut PolyVecK,
        v: *const PolyVecK,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_make_hint(
        h: *mut PolyVecK,
        v0: *const PolyVecK,
        v1: *const PolyVecK,
    ) -> cty::c_uint;
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_pack_w1(
        r: *mut [u8; params::K * params::POLYW1_PACKEDBYTES],
        w1: *const PolyVecK,
    );
    fn PQCLEAN_DILITHIUM5_CLEAN_polyveck_pointwise_poly_montgomery(
        r: *mut PolyVecK,
        a: *const Poly,
        v: *const PolyVecK,
    );
}

pub fn polyvec_matrix_expand(rho: &[u8; SEEDBYTES]) -> [PolyVecL; params::K] {
    let mut mat = MaybeUninit::<[PolyVecL; params::K]>::uninit();
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyvec_matrix_expand(mat.as_mut_ptr(), rho as *const _) };
    unsafe { mat.assume_init() }
}
pub fn polyvecl_uniform_eta(seed: &[u8; CRHBYTES], nonce: u16) -> PolyVecL {
    let mut v = MaybeUninit::<PolyVecL>::uninit();
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyvecl_uniform_eta(v.as_mut_ptr(), seed as *const _, nonce)
    };
    unsafe { v.assume_init() }
}
pub fn polyveck_uniform_eta(seed: &[u8; CRHBYTES], nonce: u16) -> PolyVecK {
    let mut v = MaybeUninit::<PolyVecK>::uninit();
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyveck_uniform_eta(v.as_mut_ptr(), seed as *const _, nonce)
    };
    unsafe { v.assume_init() }
}
pub fn polyvecl_ntt(v: &mut PolyVecL) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyvecl_ntt(v as *mut _) };
}
pub fn polyveck_reduce(v: &mut PolyVecK) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyveck_reduce(v as *mut _) };
}
pub fn polyvecl_reduce(v: &mut PolyVecL) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyvecl_reduce(v as *mut _) };
}
pub fn polyveck_invntt_tomont(v: &mut PolyVecK) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyveck_invntt_tomont(v as *mut _) };
}
pub fn polyvecl_invntt_tomont(v: &mut PolyVecL) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyvecl_invntt_tomont(v as *mut _) };
}
pub fn polyvec_matrix_pointwise_montgomery(mat: &[PolyVecL; params::K], v: &PolyVecL) -> PolyVecK {
    let mut t = MaybeUninit::<PolyVecK>::uninit();
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyvec_matrix_pointwise_montgomery(
            t.as_mut_ptr(),
            mat as *const _,
            v as *const _,
        )
    };
    unsafe { t.assume_init() }
}
pub fn polyveck_caddq(t: &mut PolyVecK) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyveck_caddq(t as *mut _) };
}
pub fn pack_pk(pk: &mut [u8; PUBLICKEYBYTES], rho: &[u8; SEEDBYTES], t1: &PolyVecK) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_pack_pk(pk as *mut _, rho as *const _, t1 as *const _) };
}
pub fn pack_sig(sig: &mut [u8; SIGNATUREBYTES], z: &PolyVecL, h: &PolyVecK) {
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_pack_sig(
            sig as *mut _,
            sig as *const _ as *const [u8; SEEDBYTES],
            z as *const _,
            h as *const _,
        )
    };
}
pub fn pack_sk(
    sk: &mut [u8; SECRETKEYBYTES],
    rho: &[u8; SEEDBYTES],
    tr: &[u8; SEEDBYTES],
    key: &[u8; SEEDBYTES],
    t0: &PolyVecK,
    s1: &PolyVecL,
    s2: &PolyVecK,
) {
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_pack_sk(
            sk as *mut _,
            rho as *const _,
            tr as *const _,
            key as *const _,
            t0 as *const _,
            s1 as *const _,
            s2 as *const _,
        )
    };
}
pub fn unpack_pk(pk: &[u8; PUBLICKEYBYTES]) -> ([u8; SEEDBYTES], PolyVecK) {
    let mut rho = MaybeUninit::<[u8; SEEDBYTES]>::uninit();
    let mut t1 = MaybeUninit::<PolyVecK>::uninit();
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_unpack_pk(rho.as_mut_ptr(), t1.as_mut_ptr(), pk as *const _)
    };
    let rho = unsafe { rho.assume_init() };
    let t1 = unsafe { t1.assume_init() };
    (rho, t1)
}
pub fn unpack_sig(sig: &[u8; SIGNATUREBYTES]) -> Result<([u8; SEEDBYTES], PolyVecL, PolyVecK), ()> {
    let mut c = MaybeUninit::<[u8; SEEDBYTES]>::uninit();
    let mut z = MaybeUninit::<PolyVecL>::uninit();
    let mut h = MaybeUninit::<PolyVecK>::uninit();
    let res = unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_unpack_sig(
            c.as_mut_ptr(),
            z.as_mut_ptr(),
            h.as_mut_ptr(),
            sig as *const _,
        )
    };
    if res != 0 {
        return Err(());
    }
    let c = unsafe { c.assume_init() };
    let z = unsafe { z.assume_init() };
    let h = unsafe { h.assume_init() };
    Ok((c, z, h))
}
pub fn unpack_sk(
    sk: &[u8; SECRETKEYBYTES],
) -> (
    [u8; SEEDBYTES],
    [u8; SEEDBYTES],
    [u8; SEEDBYTES],
    PolyVecK,
    PolyVecL,
    PolyVecK,
) {
    let mut rho = MaybeUninit::<[u8; SEEDBYTES]>::uninit();
    let mut tr = MaybeUninit::<[u8; SEEDBYTES]>::uninit();
    let mut key = MaybeUninit::<[u8; SEEDBYTES]>::uninit();
    let mut t0 = MaybeUninit::<PolyVecK>::uninit();
    let mut s1 = MaybeUninit::<PolyVecL>::uninit();
    let mut s2 = MaybeUninit::<PolyVecK>::uninit();
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_unpack_sk(
            rho.as_mut_ptr(),
            tr.as_mut_ptr(),
            key.as_mut_ptr(),
            t0.as_mut_ptr(),
            s1.as_mut_ptr(),
            s2.as_mut_ptr(),
            sk as *const _,
        )
    };
    let rho = unsafe { rho.assume_init() };
    let tr = unsafe { tr.assume_init() };
    let key = unsafe { key.assume_init() };
    let t0 = unsafe { t0.assume_init() };
    let s1 = unsafe { s1.assume_init() };
    let s2 = unsafe { s2.assume_init() };
    (rho, tr, key, t0, s1, s2)
}
pub fn polyvecl_chknorm(v: &PolyVecL, bound: i32) -> Result<(), ()> {
    let res = unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyvecl_chknorm(v as *const _, bound) };
    if res != 0 {
        return Err(());
    }
    Ok(())
}
pub fn polyveck_chknorm(v: &PolyVecK, bound: i32) -> Result<(), ()> {
    let res = unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyveck_chknorm(v as *const _, bound) };
    if res != 0 {
        return Err(());
    }
    Ok(())
}
pub fn poly_challenge(seed: &[u8; SEEDBYTES]) -> Poly {
    let mut c = MaybeUninit::<Poly>::uninit();
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_poly_challenge(c.as_mut_ptr(), seed as *const _) };
    unsafe { c.assume_init() }
}
pub fn poly_ntt(a: &mut Poly) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_poly_ntt(a as *mut _) };
}
pub fn polyveck_shiftl(v: &mut PolyVecK) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyveck_shiftl(v as *mut _) };
}
pub fn polyveck_ntt(v: &mut PolyVecK) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyveck_ntt(v as *mut _) };
}
pub fn polyvecl_pointwise_poly_montgomery(r: &mut PolyVecL, a: &Poly, v: &PolyVecL) {
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyvecl_pointwise_poly_montgomery(
            r as *mut _,
            a as *const _,
            v as *const _,
        )
    };
}
/// Add the vector of polynomials `v` into the vector of polynomials `w`
/// in-place, modifying `w`.
pub fn polyveck_add_inplace(w: &mut PolyVecK, v: &PolyVecK) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyveck_add(w as *mut _, w as *const _, v as *const _) };
}
/// Add the vector of polynomials `v` into the vector of polynomials `w`
/// in-place, modifying `w`.
pub fn polyvecl_add_inplace(w: &mut PolyVecL, v: &PolyVecL) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyvecl_add(w as *mut _, w as *const _, v as *const _) };
}
/// Subtract the vector of polynomials `v` from the vector of polynomials `w`
/// in-place, modifying `w`.
pub fn polyveck_sub_inplace(w: &mut PolyVecK, v: &PolyVecK) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyveck_sub(w as *mut _, w as *const _, v as *const _) };
}
/// Round the vector of polynomials `v1` to 2^D in-place, returning a vector of
/// polynomials with the differences.
pub fn polyveck_power2round_inplace(v1: &mut PolyVecK) -> PolyVecK {
    let mut v0 = MaybeUninit::<PolyVecK>::uninit();
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyveck_power2round(v1 as *mut _, v0.as_mut_ptr(), v1 as *const _)
    };
    unsafe { v0.assume_init() }
}
/// Apply hint vector of polynomials `h` inplace to `w`.
pub fn polyveck_use_hint_inplace(w: &mut PolyVecK, h: &PolyVecK) {
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyveck_use_hint(w as *mut _, w as *const _, h as *const _)
    };
}
pub fn polyvecl_uniform_gamma1(seed: &[u8; CRHBYTES], nonce: u16) -> PolyVecL {
    let mut v = MaybeUninit::<PolyVecL>::uninit();
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyvecl_uniform_gamma1(v.as_mut_ptr(), seed as *const _, nonce)
    };
    unsafe { v.assume_init() }
}
/// Decompose the vector of polynomials `v1` to high bits (in-place) and low
/// bits (returned).
pub fn polyveck_decompose_inplace(v1: &mut PolyVecK) -> PolyVecK {
    let mut v0 = MaybeUninit::<PolyVecK>::uninit();
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyveck_decompose(v1 as *mut _, v0.as_mut_ptr(), v1 as *const _)
    };
    unsafe { v0.assume_init() }
}
pub fn polyveck_make_hint(h: &mut PolyVecK, v0: &PolyVecK, v1: &PolyVecK) -> cty::c_uint {
    let res = unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyveck_make_hint(h as *mut _, v0 as *const _, v1 as *const _)
    };
    res
}
pub fn polyveck_pack_w1(r: &mut [u8; params::K * params::POLYW1_PACKEDBYTES], w1: &PolyVecK) {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyveck_pack_w1(r as *mut _, w1 as *const _) };
}
pub fn polyveck_pack_w1_new(w1: &PolyVecK) -> [u8; params::K * params::POLYW1_PACKEDBYTES] {
    let mut r = MaybeUninit::<[u8; params::K * params::POLYW1_PACKEDBYTES]>::uninit();
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_polyveck_pack_w1(r.as_mut_ptr(), w1 as *const _) };
    unsafe { r.assume_init() }
}
pub fn polyveck_pointwise_poly_montgomery(r: &mut PolyVecK, a: &Poly, v: &PolyVecK) {
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyveck_pointwise_poly_montgomery(
            r as *mut _,
            a as *const _,
            v as *const _,
        )
    };
}
pub fn polyveck_pointwise_poly_montgomery_new(a: &Poly, v: &PolyVecK) -> PolyVecK {
    let mut r = MaybeUninit::<PolyVecK>::uninit();
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyveck_pointwise_poly_montgomery(
            r.as_mut_ptr(),
            a as *const _,
            v as *const _,
        )
    };
    unsafe { r.assume_init() }
}
/// `polyveck_pointwise_poly_montgomery` with `r == v`.
pub fn polyveck_pointwise_poly_montgomery_inplace(r: &mut PolyVecK, a: &Poly) {
    unsafe {
        PQCLEAN_DILITHIUM5_CLEAN_polyveck_pointwise_poly_montgomery(
            r as *mut _,
            a as *const _,
            r as *const _,
        )
    };
}
