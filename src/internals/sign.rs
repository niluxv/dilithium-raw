//! Implementation of dilithium `sign.c` ported to Rust, provided by a macro so
//! it can be generated for all levels of dilithium and for both `clean` and
//! `aarch64` implementations.

macro_rules! sign_api {
    () => {
        use crate::util::{slice_as_array, slice_as_array_mut};
        use crate::{VerificationFailure, VerificationOk, VerificationResult};
        use sha3::digest::{ExtendableOutput, ExtendableOutputReset, Update};

        pub fn crypto_sign_keypair(
            pk: &mut [u8; PUBLICKEYBYTES],
            sk: &mut [u8; SECRETKEYBYTES],
            random: &mut [u8; 2 * SEEDBYTES + CRHBYTES],
        ) {
            let rho = slice_as_array::<u8, SEEDBYTES>(&random[..SEEDBYTES]);
            let rhoprime = slice_as_array::<u8, CRHBYTES>(&random[SEEDBYTES..SEEDBYTES + CRHBYTES]);
            // why is the range `2*SEEDBYTES .. 3*SEEDBYTES` unused? note that `CRHBYTES ==
            // 2* SEEDBYTES`
            let key = slice_as_array::<u8, SEEDBYTES>(
                &random[SEEDBYTES + CRHBYTES..2 * SEEDBYTES + CRHBYTES]
            );

            /* Expand matrix */
            let mat = ffi::polyvec_matrix_expand(rho);

            /* Sample short vectors s1 and s2 */
            let s1 = ffi::polyvecl_uniform_eta(rhoprime, 0);
            let s2 = ffi::polyveck_uniform_eta(rhoprime, params::L as u16);

            /* Matrix-vector multiplication */
            let mut s1hat = s1.clone();
            ffi::polyvecl_ntt(&mut s1hat);
            let mut t1 = ffi::polyvec_matrix_pointwise_montgomery(&mat, &s1hat);
            ffi::polyveck_reduce(&mut t1);
            ffi::polyveck_invntt_tomont(&mut t1);

            /* Add error vector s2 */
            ffi::polyveck_add_inplace(&mut t1, &s2);

            /* Extract t1 and write public key */
            ffi::polyveck_caddq(&mut t1);
            let t0 = ffi::polyveck_power2round_inplace(&mut t1);
            ffi::pack_pk(pk, rho, &t1);

            /* Compute H(rho, t1) and write secret key */
            let mut state = sha3::Shake256::default();
            state.update(pk.as_ref());
            let mut tr = [0u8; SEEDBYTES];
            state.finalize_xof_into(tr.as_mut());
            ffi::pack_sk(sk, rho, &tr, key, &t0, &s1, &s2);
        }

        pub fn crypto_sign_signature(
            sig: &mut [u8; SIGNATUREBYTES],
            msg: &[u8],
            sk: &[u8; SECRETKEYBYTES],
        ) {
            let (rho, tr, key, mut t0, mut s1, mut s2) = ffi::unpack_sk(sk);

            // Compute `mu = CRH(tr, msg)`
            let mut state = sha3::Shake256::default();
            state.update(tr.as_ref());
            state.update(msg);
            let mut mu = [0; CRHBYTES];
            state.finalize_xof_reset_into(mu.as_mut());
            // compute `rhoprime = CRH(key, mu)`
            state.update(key.as_ref());
            state.update(mu.as_ref());
            let mut rhoprime = [0; CRHBYTES];
            state.finalize_xof_reset_into(rhoprime.as_mut());

            /* Expand matrix and transform vectors */
            let mat = ffi::polyvec_matrix_expand(&rho);
            ffi::polyvecl_ntt(&mut s1);
            ffi::polyveck_ntt(&mut s2);
            ffi::polyveck_ntt(&mut t0);

            let mut nonce: u16 = 0;
            loop {
                /* Sample intermediate vector y */
                let y = ffi::polyvecl_uniform_gamma1(&rhoprime, nonce);
                nonce += 1;

                /* Matrix-vector multiplication */
                let mut z = y.clone();
                ffi::polyvecl_ntt(&mut z);
                let mut w1 = ffi::polyvec_matrix_pointwise_montgomery(&mat, &z);
                ffi::polyveck_reduce(&mut w1);
                ffi::polyveck_invntt_tomont(&mut w1);

                /* Decompose w and call the random oracle */
                ffi::polyveck_caddq(&mut w1);
                let mut w0 = ffi::polyveck_decompose_inplace(&mut w1);
                let sig_slice =
                    slice_as_array_mut::<u8, { params::K * params::POLYW1_PACKEDBYTES }>(
                        &mut sig[..params::K * params::POLYW1_PACKEDBYTES],
                    );
                ffi::polyveck_pack_w1(sig_slice, &w1);

                state.update(mu.as_ref());
                state.update(&sig[..params::K * params::POLYW1_PACKEDBYTES]);
                state.finalize_xof_reset_into(&mut sig[..SEEDBYTES]);

                let sig_slice = slice_as_array_mut::<u8, SEEDBYTES>(&mut sig[..SEEDBYTES]);
                let mut cp = ffi::poly_challenge(sig_slice);
                ffi::poly_ntt(&mut cp);

                /* Compute z, reject if it reveals secret */
                ffi::polyvecl_pointwise_poly_montgomery(&mut z, &cp, &s1);
                ffi::polyvecl_invntt_tomont(&mut z);
                ffi::polyvecl_add_inplace(&mut z, &y);
                ffi::polyvecl_reduce(&mut z);
                if ffi::polyvecl_chknorm(&z, (params::GAMMA1 - params::BETA) as i32).is_err() {
                    continue;
                }

                /* Check that subtracting cs2 does not change high bits of w and low bits
                * do not reveal secret information */
                let mut h = ffi::polyveck_pointwise_poly_montgomery_new(&cp, &s2);
                ffi::polyveck_invntt_tomont(&mut h);
                ffi::polyveck_sub_inplace(&mut w0, &h);
                ffi::polyveck_reduce(&mut w0);
                if ffi::polyveck_chknorm(&w0, (params::GAMMA2 - params::BETA) as i32).is_err() {
                    continue;
                }

                /* Compute hints for w1 */
                ffi::polyveck_pointwise_poly_montgomery(&mut h, &cp, &t0);
                ffi::polyveck_invntt_tomont(&mut h);
                ffi::polyveck_reduce(&mut h);
                if ffi::polyveck_chknorm(&h, params::GAMMA2 as i32).is_err() {
                    continue;
                }

                ffi::polyveck_add_inplace(&mut w0, &h);
                let n = ffi::polyveck_make_hint(&mut h, &w0, &w1);
                if n > params::OMEGA as cty::c_uint {
                    continue;
                }

                /* Write signature */
                ffi::pack_sig(sig, &z, &h);
                return;
            }
        }

        pub fn crypto_sign_verify(
            sig: &[u8; SIGNATUREBYTES],
            msg: &[u8],
            pk: &[u8; PUBLICKEYBYTES],
        ) -> VerificationResult {
            let (rho, mut t1) = ffi::unpack_pk(pk);
            let (c, mut z, h) = ffi::unpack_sig(sig).map_err(|_| VerificationFailure)?;
            if ffi::polyvecl_chknorm(&z, (params::GAMMA1 - params::BETA) as i32).is_err() {
                return Err(VerificationFailure);
            }

            /* Compute CRH(H(rho, t1), msg) */
            let mut state = sha3::Shake256::default();
            // compute `mu = H(pk)`
            state.update(pk);
            let mut mu: [u8; CRHBYTES] = [0; CRHBYTES];
            state.finalize_xof_reset_into(&mut mu[..SEEDBYTES]);
            // compute `mu = CRH(mu, msg)`
            state.update(&mu[..SEEDBYTES]);
            state.update(msg);
            state.finalize_xof_reset_into(mu.as_mut());

            /* Matrix-vector multiplication; compute Az - c2^dt1 */
            let mut cp = ffi::poly_challenge(&c);
            let mat = ffi::polyvec_matrix_expand(&rho);

            ffi::polyvecl_ntt(&mut z);
            let mut w1 = ffi::polyvec_matrix_pointwise_montgomery(&mat, &z);

            ffi::poly_ntt(&mut cp);
            ffi::polyveck_shiftl(&mut t1);
            ffi::polyveck_ntt(&mut t1);
            ffi::polyveck_pointwise_poly_montgomery_inplace(&mut t1, &cp);

            ffi::polyveck_sub_inplace(&mut w1, &t1);
            ffi::polyveck_reduce(&mut w1);
            ffi::polyveck_invntt_tomont(&mut w1);

            /* Reconstruct w1 */
            ffi::polyveck_caddq(&mut w1);
            ffi::polyveck_use_hint_inplace(&mut w1, &h);
            let buf = ffi::polyveck_pack_w1_new(&w1);

            /* Call random oracle and verify PQCLEAN_DILITHIUM5_CLEAN_challenge */
            state.update(mu.as_ref());
            state.update(buf.as_ref());
            let mut c2 = [0; SEEDBYTES];
            state.finalize_xof_into(c2.as_mut());

            if c == c2 {
                Ok(VerificationOk)
            } else {
                Err(VerificationFailure)
            }
        }
    }
}

pub(crate) use sign_api;
