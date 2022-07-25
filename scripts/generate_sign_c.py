import json

def main():
    with open("scripts/dilithium.json", 'r') as json_file:
        spec = json.load(json_file)

    for param_set in spec["parameter_sets"]:
        level = param_set["security_level"]
        for impl in param_set["implementations"]:
            assert impl in ["clean", "avx2", "aarch64"]
            IMPL = impl.upper()
            keypair_decl = f"""\
/*************************************************
* Name:        PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t pk[DILITHIUM_NAMESPACE(CRYPTO_PUBLICKEYBYTES)]:
*                       pointer to output public key (allocated
*                       array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t sk[DILITHIUM_NAMESPACE(CRYPTO_SECRETKEYBYTES)]:
*                       pointer to output private key (allocated
*                       array of CRYPTO_SECRETKEYBYTES bytes)
*              - uint8_t random[2 * SEEDBYTES + CRHBYTES]:
*                       pointer to array filled with random bytes;
*                       needs to live until the function returns
*
* Returns 0 (success)
**************************************************/
int DILITHIUM_NAMESPACE(crypto_sign_keypair)(
    uint8_t pk[DILITHIUM_NAMESPACE(CRYPTO_PUBLICKEYBYTES)],
    uint8_t sk[DILITHIUM_NAMESPACE(CRYPTO_SECRETKEYBYTES)],
    uint8_t random[2 * SEEDBYTES + CRHBYTES]
) {{"""

            sign_signature_decl = f"""\
/*************************************************
* Name:        PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t* sig:   pointer to output signature (allocated array
*                       of CRYPTO_BYTES bytes)
*              - uint8_t* m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - const uint8_t sk[DILITHIUM_NAMESPACE(CRYPTO_SECRETKEYBYTES)]:
*                       pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int DILITHIUM_NAMESPACE(crypto_sign_signature)(
    uint8_t* sig,
    const uint8_t* m, size_t mlen,
    const uint8_t sk[DILITHIUM_NAMESPACE(CRYPTO_SECRETKEYBYTES)]
) {{"""

            sign_verify_decl = f"""\
/*************************************************
* Name:        PQCLEAN_DILITHIUM{level}_{IMPL}_crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t* m:        pointer to input signature
*              - const uint8_t* m:  pointer to message
*              - size_t mlen:       length of message
*              - const uint8_t pk[DILITHIUM_NAMESPACE(CRYPTO_PUBLICKEYBYTES)]:
*                       pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int DILITHIUM_NAMESPACE(crypto_sign_verify)(
    const uint8_t* sig,
    const uint8_t* m, size_t mlen,
    const uint8_t pk[DILITHIUM_NAMESPACE(CRYPTO_PUBLICKEYBYTES)]
) {{"""

            if impl == "clean":
                template = f"""\
#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"
#include "symmetric.h"
#include <stdint.h>

{keypair_decl}
    uint8_t tr[SEEDBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    rho = random;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvec_matrix_expand(mat, rho);

    /* Sample short vectors s1 and s2 */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_uniform_eta(&s1, rhoprime, 0);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_uniform_eta(&s2, rhoprime, L);

    /* Matrix-vector multiplication */
    s1hat = s1;
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_ntt(&s1hat);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_reduce(&t1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_invntt_tomont(&t1);

    /* Add error vector s2 */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_add(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_caddq(&t1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_power2round(&t1, &t0, &t1);
    PQCLEAN_DILITHIUM{level}_CLEAN_pack_pk(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256(tr, SEEDBYTES, pk, PQCLEAN_DILITHIUM{level}_CLEAN_CRYPTO_PUBLICKEYBYTES);
    PQCLEAN_DILITHIUM{level}_CLEAN_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}}

{sign_signature_decl}
    unsigned int n;
    uint8_t seedbuf[3 * SEEDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint16_t nonce = 0;
    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + SEEDBYTES;
    mu = key + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    PQCLEAN_DILITHIUM{level}_CLEAN_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute CRH(tr, msg) */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);

    /* Expand matrix and transform vectors */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvec_matrix_expand(mat, rho);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_ntt(&s1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_ntt(&s2);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_ntt(&t0);

rej:
    /* Sample intermediate vector y */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_invntt_tomont(&w1);

    /* Decompose w and call the random oracle */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_decompose(&w1, &w0, &w1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_pack_w1(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, SEEDBYTES, &state);
    shake256_inc_ctx_release(&state);
    PQCLEAN_DILITHIUM{level}_CLEAN_poly_challenge(&cp, sig);
    PQCLEAN_DILITHIUM{level}_CLEAN_poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_invntt_tomont(&z);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_add(&z, &z, &y);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_reduce(&z);
    if (PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {{
        goto rej;
    }}

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_sub(&w0, &w0, &h);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_reduce(&w0);
    if (PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_chknorm(&w0, GAMMA2 - BETA)) {{
        goto rej;
    }}

    /* Compute hints for w1 */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_reduce(&h);
    if (PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_chknorm(&h, GAMMA2)) {{
        goto rej;
    }}

    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_add(&w0, &w0, &h);
    n = PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {{
        goto rej;
    }}

    /* Write signature */
    PQCLEAN_DILITHIUM{level}_CLEAN_pack_sig(sig, sig, &z, &h);
    return 0;
}}

{sign_verify_decl}
    unsigned int i;
    uint8_t buf[K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[SEEDBYTES];
    uint8_t c2[SEEDBYTES];
    poly cp;
    polyvecl mat[K], z;
    polyveck t1, w1, h;
    shake256incctx state;

    PQCLEAN_DILITHIUM{level}_CLEAN_unpack_pk(rho, &t1, pk);
    if (PQCLEAN_DILITHIUM{level}_CLEAN_unpack_sig(c, &z, &h, sig)) {{
        return -1;
    }}
    if (PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {{
        return -1;
    }}

    /* Compute CRH(H(rho, t1), msg) */
    shake256(mu, SEEDBYTES, pk, PQCLEAN_DILITHIUM{level}_CLEAN_CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    PQCLEAN_DILITHIUM{level}_CLEAN_poly_challenge(&cp, c);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvec_matrix_expand(mat, rho);

    PQCLEAN_DILITHIUM{level}_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    PQCLEAN_DILITHIUM{level}_CLEAN_poly_ntt(&cp);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_shiftl(&t1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_ntt(&t1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_sub(&w1, &w1, &t1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_invntt_tomont(&w1);

    /* Reconstruct w1 */
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_use_hint(&w1, &w1, &h);
    PQCLEAN_DILITHIUM{level}_CLEAN_polyveck_pack_w1(buf, &w1);

    /* Call random oracle and verify PQCLEAN_DILITHIUM{level}_CLEAN_challenge */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, SEEDBYTES, &state);
    shake256_inc_ctx_release(&state);
    for (i = 0; i < SEEDBYTES; ++i) {{
        if (c[i] != c2[i]) {{
            return -1;
        }}
    }}

    return 0;
}}
"""
            elif impl == "avx2":
                polyvec_matrix_expand_row_cases_4_5 = f"""
    case 4:
        PQCLEAN_DILITHIUM{level}_AVX2_polyvec_matrix_expand_row4(buf, buf + 1, rho);
        *row = buf;
        break;
    case 5:
        PQCLEAN_DILITHIUM{level}_AVX2_polyvec_matrix_expand_row5(buf + 1, buf, rho);
        *row = buf + 1;
        break;"""

                polyvec_matrix_expand_row_cases_6_7 = f"""
    case 6:
        PQCLEAN_DILITHIUM{level}_AVX2_polyvec_matrix_expand_row6(buf, buf + 1, rho);
        *row = buf;
        break;
    case 7:
        PQCLEAN_DILITHIUM{level}_AVX2_polyvec_matrix_expand_row7(buf + 1, buf, rho);
        *row = buf + 1;
        break;"""

                if level == 2:
                    polyvec_matrix_expand_row_cases_4_5 = ""
                    polyvec_matrix_expand_row_cases_6_7 = ""
                    sample_short_vectors_code = f"""\
    PQCLEAN_DILITHIUM{level}_AVX2_poly_uniform_eta_4x(&s2.vec[0], &s2.vec[1], &s2.vec[2], &s2.vec[3], rhoprime, 4, 5, 6, 7);"""
                    sample_intermediate_vector_code = f"""\
    nonce += 4;"""
                elif level == 3:
                    polyvec_matrix_expand_row_cases_6_7 = ""
                    sample_short_vectors_code = f"""\
    PQCLEAN_DILITHIUM{level}_AVX2_poly_uniform_eta_4x(&s1.vec[4], &s2.vec[0], &s2.vec[1], &s2.vec[2], rhoprime, 4, 5, 6, 7);
    PQCLEAN_DILITHIUM{level}_AVX2_poly_uniform_eta_4x(&s2.vec[3], &s2.vec[4], &s2.vec[5], &t0, rhoprime, 8, 9, 10, 11);"""
                    sample_intermediate_vector_code = f"""\
    PQCLEAN_DILITHIUM3_AVX2_poly_uniform_gamma1(&z.vec[4], rhoprime, nonce + 4);
    nonce += 5;"""
                elif level == 5:
                    sample_short_vectors_code = f"""\
    PQCLEAN_DILITHIUM{level}_AVX2_poly_uniform_eta_4x(&s1.vec[4], &s1.vec[5], &s1.vec[6], &s2.vec[0], rhoprime, 4, 5, 6, 7);
    PQCLEAN_DILITHIUM{level}_AVX2_poly_uniform_eta_4x(&s2.vec[1], &s2.vec[2], &s2.vec[3], &s2.vec[4], rhoprime, 8, 9, 10, 11);
    PQCLEAN_DILITHIUM{level}_AVX2_poly_uniform_eta_4x(&s2.vec[5], &s2.vec[6], &s2.vec[7], &t0, rhoprime, 12, 13, 14, 15);"""
                    sample_intermediate_vector_code = f"""\
    PQCLEAN_DILITHIUM{level}_AVX2_poly_uniform_gamma1_4x(&z.vec[4], &z.vec[5], &z.vec[6], &tmp,
            rhoprime, nonce + 4, nonce + 5, nonce + 6, 0);
    nonce += 7;"""

                template = f"""\
#include "align.h"
#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"
#include "symmetric.h"
#include <stdint.h>
#include <string.h>

static inline void polyvec_matrix_expand_row(polyvecl **row, polyvecl buf[2], const uint8_t rho[SEEDBYTES], unsigned int i) {{
    switch (i) {{
    case 0:
        PQCLEAN_DILITHIUM{level}_AVX2_polyvec_matrix_expand_row0(buf, buf + 1, rho);
        *row = buf;
        break;
    case 1:
        PQCLEAN_DILITHIUM{level}_AVX2_polyvec_matrix_expand_row1(buf + 1, buf, rho);
        *row = buf + 1;
        break;
    case 2:
        PQCLEAN_DILITHIUM{level}_AVX2_polyvec_matrix_expand_row2(buf, buf + 1, rho);
        *row = buf;
        break;
    case 3:
        PQCLEAN_DILITHIUM{level}_AVX2_polyvec_matrix_expand_row3(buf + 1, buf, rho);
        *row = buf + 1;
        break;{polyvec_matrix_expand_row_cases_4_5}{polyvec_matrix_expand_row_cases_6_7}
    }}
}}

{keypair_decl}
    unsigned int i;
    const uint8_t *rho, *rhoprime, *key;
    polyvecl rowbuf[2];
    polyvecl s1, *row = rowbuf;
    polyveck s2;
    poly t1, t0;

    rho = random;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Store rho, key */
    memcpy(pk, rho, SEEDBYTES);
    memcpy(sk, rho, SEEDBYTES);
    memcpy(sk + SEEDBYTES, key, SEEDBYTES);

    /* Sample short vectors s1 and s2 */
    PQCLEAN_DILITHIUM{level}_AVX2_poly_uniform_eta_4x(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3], rhoprime, 0, 1, 2, 3);
{sample_short_vectors_code}

    /* Pack secret vectors */
    for (i = 0; i < L; i++) {{
        PQCLEAN_DILITHIUM{level}_AVX2_polyeta_pack(sk + 3 * SEEDBYTES + i * POLYETA_PACKEDBYTES, &s1.vec[i]);
    }}
    for (i = 0; i < K; i++) {{
        PQCLEAN_DILITHIUM{level}_AVX2_polyeta_pack(sk + 3 * SEEDBYTES + (L + i)*POLYETA_PACKEDBYTES, &s2.vec[i]);
    }}

    /* Transform s1 */
    PQCLEAN_DILITHIUM{level}_AVX2_polyvecl_ntt(&s1);


    for (i = 0; i < K; i++) {{
        /* Expand matrix row */
        polyvec_matrix_expand_row(&row, rowbuf, rho, i);

        /* Compute inner-product */
        PQCLEAN_DILITHIUM{level}_AVX2_polyvecl_pointwise_acc_montgomery(&t1, row, &s1);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_invntt_tomont(&t1);

        /* Add error polynomial */
        PQCLEAN_DILITHIUM{level}_AVX2_poly_add(&t1, &t1, &s2.vec[i]);

        /* Round t and pack t1, t0 */
        PQCLEAN_DILITHIUM{level}_AVX2_poly_caddq(&t1);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_power2round(&t1, &t0, &t1);
        PQCLEAN_DILITHIUM{level}_AVX2_polyt1_pack(pk + SEEDBYTES + i * POLYT1_PACKEDBYTES, &t1);
        PQCLEAN_DILITHIUM{level}_AVX2_polyt0_pack(sk + 3 * SEEDBYTES + (L + K)*POLYETA_PACKEDBYTES + i * POLYT0_PACKEDBYTES, &t0);
    }}

    /* Compute H(rho, t1) and store in secret key */
    shake256(sk + 2 * SEEDBYTES, SEEDBYTES, pk, PQCLEAN_DILITHIUM{level}_AVX2_CRYPTO_PUBLICKEYBYTES);

    return 0;
}}

{sign_signature_decl}
    unsigned int i, n, pos;
    uint8_t seedbuf[3 * SEEDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint8_t hintbuf[N];
    uint8_t *hint = sig + SEEDBYTES + L * POLYZ_PACKEDBYTES;
    uint64_t nonce = 0;
    polyvecl mat[K], s1, z;
    polyveck t0, s2, w1;
    poly c, tmp;
    union {{
        polyvecl y;
        polyveck w0;
    }} tmpv;
    shake256incctx state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + SEEDBYTES;
    mu = key + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    PQCLEAN_DILITHIUM{level}_AVX2_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute CRH(tr, msg) */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);

    /* Expand matrix and transform vectors */
    PQCLEAN_DILITHIUM{level}_AVX2_polyvec_matrix_expand(mat, rho);
    PQCLEAN_DILITHIUM{level}_AVX2_polyvecl_ntt(&s1);
    PQCLEAN_DILITHIUM{level}_AVX2_polyveck_ntt(&s2);
    PQCLEAN_DILITHIUM{level}_AVX2_polyveck_ntt(&t0);


rej:
    /* Sample intermediate vector y */
    PQCLEAN_DILITHIUM{level}_AVX2_poly_uniform_gamma1_4x(&z.vec[0], &z.vec[1], &z.vec[2], &z.vec[3],
            rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
{sample_intermediate_vector_code}

    /* Matrix-vector product */
    tmpv.y = z;
    PQCLEAN_DILITHIUM{level}_AVX2_polyvecl_ntt(&tmpv.y);
    PQCLEAN_DILITHIUM{level}_AVX2_polyvec_matrix_pointwise_montgomery(&w1, mat, &tmpv.y);
    PQCLEAN_DILITHIUM{level}_AVX2_polyveck_invntt_tomont(&w1);

    /* Decompose w and call the random oracle */
    PQCLEAN_DILITHIUM{level}_AVX2_polyveck_caddq(&w1);
    PQCLEAN_DILITHIUM{level}_AVX2_polyveck_decompose(&w1, &tmpv.w0, &w1);
    PQCLEAN_DILITHIUM{level}_AVX2_polyveck_pack_w1(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, SEEDBYTES, &state);
    shake256_inc_ctx_release(&state);
    PQCLEAN_DILITHIUM{level}_AVX2_poly_challenge(&c, sig);
    PQCLEAN_DILITHIUM{level}_AVX2_poly_ntt(&c);

    /* Compute z, reject if it reveals secret */
    for (i = 0; i < L; i++) {{
        PQCLEAN_DILITHIUM{level}_AVX2_poly_pointwise_montgomery(&tmp, &c, &s1.vec[i]);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_invntt_tomont(&tmp);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_add(&z.vec[i], &z.vec[i], &tmp);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_reduce(&z.vec[i]);
        if (PQCLEAN_DILITHIUM{level}_AVX2_poly_chknorm(&z.vec[i], GAMMA1 - BETA)) {{
            goto rej;
        }}
    }}

    /* Zero hint vector in signature */
    pos = 0;
    memset(hint, 0, OMEGA);

    for (i = 0; i < K; i++) {{
        /* Check that subtracting cs2 does not change high bits of w and low bits
         * do not reveal secret information */
        PQCLEAN_DILITHIUM{level}_AVX2_poly_pointwise_montgomery(&tmp, &c, &s2.vec[i]);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_invntt_tomont(&tmp);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_sub(&tmpv.w0.vec[i], &tmpv.w0.vec[i], &tmp);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_reduce(&tmpv.w0.vec[i]);
        if (PQCLEAN_DILITHIUM{level}_AVX2_poly_chknorm(&tmpv.w0.vec[i], GAMMA2 - BETA)) {{
            goto rej;
        }}

        /* Compute hints */
        PQCLEAN_DILITHIUM{level}_AVX2_poly_pointwise_montgomery(&tmp, &c, &t0.vec[i]);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_invntt_tomont(&tmp);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_reduce(&tmp);
        if (PQCLEAN_DILITHIUM{level}_AVX2_poly_chknorm(&tmp, GAMMA2)) {{
            goto rej;
        }}

        PQCLEAN_DILITHIUM{level}_AVX2_poly_add(&tmpv.w0.vec[i], &tmpv.w0.vec[i], &tmp);
        n = PQCLEAN_DILITHIUM{level}_AVX2_poly_make_hint(hintbuf, &tmpv.w0.vec[i], &w1.vec[i]);
        if (pos + n > OMEGA) {{
            goto rej;
        }}

        /* Store hints in signature */
        memcpy(&hint[pos], hintbuf, n);
        hint[OMEGA + i] = pos = pos + n;
    }}

    /* Pack z into signature */
    for (i = 0; i < L; i++) {{
        PQCLEAN_DILITHIUM{level}_AVX2_polyz_pack(sig + SEEDBYTES + i * POLYZ_PACKEDBYTES, &z.vec[i]);
    }}

    return 0;
}}

{sign_verify_decl}
    unsigned int i, j, pos = 0;
    /* PQCLEAN_DILITHIUM{level}_AVX2_polyw1_pack writes additional 14 bytes */
    ALIGNED_UINT8(K * POLYW1_PACKEDBYTES + 14) buf;
    uint8_t mu[CRHBYTES];
    const uint8_t *hint = sig + SEEDBYTES + L * POLYZ_PACKEDBYTES;
    polyvecl rowbuf[2];
    polyvecl *row = rowbuf;
    polyvecl z;
    poly c, w1, h;
    shake256incctx state;

    /* Compute CRH(H(rho, t1), msg) */
    shake256(mu, SEEDBYTES, pk, PQCLEAN_DILITHIUM{level}_AVX2_CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    /* Expand PQCLEAN_DILITHIUM{level}_AVX2_challenge */
    PQCLEAN_DILITHIUM{level}_AVX2_poly_challenge(&c, sig);
    PQCLEAN_DILITHIUM{level}_AVX2_poly_ntt(&c);

    /* Unpack z; shortness follows from unpacking */
    for (i = 0; i < L; i++) {{
        PQCLEAN_DILITHIUM{level}_AVX2_polyz_unpack(&z.vec[i], sig + SEEDBYTES + i * POLYZ_PACKEDBYTES);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_ntt(&z.vec[i]);
    }}


    for (i = 0; i < K; i++) {{
        /* Expand matrix row */
        polyvec_matrix_expand_row(&row, rowbuf, pk, i);

        /* Compute i-th row of Az - c2^Dt1 */
        PQCLEAN_DILITHIUM{level}_AVX2_polyvecl_pointwise_acc_montgomery(&w1, row, &z);

        PQCLEAN_DILITHIUM{level}_AVX2_polyt1_unpack(&h, pk + SEEDBYTES + i * POLYT1_PACKEDBYTES);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_shiftl(&h);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_ntt(&h);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_pointwise_montgomery(&h, &c, &h);

        PQCLEAN_DILITHIUM{level}_AVX2_poly_sub(&w1, &w1, &h);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_reduce(&w1);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_invntt_tomont(&w1);

        /* Get hint polynomial and reconstruct w1 */
        memset(h.vec, 0, sizeof(poly));
        if (hint[OMEGA + i] < pos || hint[OMEGA + i] > OMEGA) {{
            return -1;
        }}

        for (j = pos; j < hint[OMEGA + i]; ++j) {{
            /* Coefficients are ordered for strong unforgeability */
            if (j > pos && hint[j] <= hint[j - 1]) {{
                return -1;
            }}
            h.coeffs[hint[j]] = 1;
        }}
        pos = hint[OMEGA + i];

        PQCLEAN_DILITHIUM{level}_AVX2_poly_caddq(&w1);
        PQCLEAN_DILITHIUM{level}_AVX2_poly_use_hint(&w1, &w1, &h);
        PQCLEAN_DILITHIUM{level}_AVX2_polyw1_pack(buf.coeffs + i * POLYW1_PACKEDBYTES, &w1);
    }}

    /* Extra indices are zero for strong unforgeability */
    for (j = pos; j < OMEGA; ++j) {{
        if (hint[j]) {{
            return -1;
        }}
    }}

    /* Call random oracle and verify PQCLEAN_DILITHIUM{level}_AVX2_challenge */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf.coeffs, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(buf.coeffs, SEEDBYTES, &state);
    shake256_inc_ctx_release(&state);
    for (i = 0; i < SEEDBYTES; ++i) {{
        if (buf.coeffs[i] != sig[i]) {{
            return -1;
        }}
    }}

    return 0;
}}
"""
            elif impl == "aarch64":
                template = f"""\
#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"
#include "symmetric.h"
#include <stdint.h>

{keypair_decl}
    uint8_t tr[SEEDBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    rho = random;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    polyvec_matrix_expand(mat, rho);

    /* Sample short vectors s1 and s2 */
    polyvecl_uniform_eta(&s1, rhoprime, 0);
    polyveck_uniform_eta(&s2, rhoprime, L);

    /* Matrix-vector multiplication */
    s1hat = s1;
    polyvecl_ntt(&s1hat);
    polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    polyveck_reduce(&t1);
    polyveck_invntt_tomont(&t1);

    /* Add error vector s2 */
    polyveck_add(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    polyveck_caddq(&t1);
    polyveck_power2round(&t1, &t0, &t1);
    pack_pk(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256(tr, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}}

{sign_signature_decl}
    unsigned int n;
    uint8_t seedbuf[3 * SEEDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint16_t nonce = 0;
    polyvecl mat[K], s1, y, z;
    polyveck t0, s2, w1, w0, h;
    poly cp;
    shake256incctx state;

    rho = seedbuf;
    tr = rho + SEEDBYTES;
    key = tr + SEEDBYTES;
    mu = key + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute CRH(tr, msg) */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);

    /* Expand matrix and transform vectors */
    polyvec_matrix_expand(mat, rho);
    polyvecl_ntt(&s1);
    polyveck_ntt(&s2);
    polyveck_ntt(&t0);

rej:
    /* Sample intermediate vector y */
    polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    polyvecl_ntt(&z);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);

    /* Decompose w and call the random oracle */
    polyveck_caddq(&w1);
    polyveck_decompose(&w1, &w0, &w1);
    polyveck_pack_w1(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, SEEDBYTES, &state);
    shake256_inc_ctx_release(&state);
    poly_challenge(&cp, sig);
    poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    polyvecl_invntt_tomont(&z);
    polyvecl_add(&z, &z, &y);
    polyvecl_reduce(&z);
    if (polyvecl_chknorm(&z, GAMMA1 - BETA)) {{
        goto rej;
    }}

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    polyveck_invntt_tomont(&h);
    polyveck_sub(&w0, &w0, &h);
    polyveck_reduce(&w0);
    if (polyveck_chknorm(&w0, GAMMA2 - BETA)) {{
        goto rej;
    }}

    /* Compute hints for w1 */
    polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    polyveck_invntt_tomont(&h);
    polyveck_reduce(&h);
    if (polyveck_chknorm(&h, GAMMA2)) {{
        goto rej;
    }}

    polyveck_add(&w0, &w0, &h);
    n = polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {{
        goto rej;
    }}

    /* Write signature */
    pack_sig(sig, sig, &z, &h);
    return 0;
}}

{sign_verify_decl}
    unsigned int i;
    uint8_t buf[K * POLYW1_PACKEDBYTES];
    uint8_t rho[SEEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[SEEDBYTES];
    uint8_t c2[SEEDBYTES];
    poly cp;
    polyvecl mat[K], z;
    polyveck t1, w1, h;
    shake256incctx state;

    unpack_pk(rho, &t1, pk);
    if (unpack_sig(c, &z, &h, sig)) {{
        return -1;
    }}
    if (polyvecl_chknorm(&z, GAMMA1 - BETA)) {{
        return -1;
    }}

    /* Compute CRH(H(rho, t1), msg) */
    shake256(mu, SEEDBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    poly_challenge(&cp, c);
    polyvec_matrix_expand(mat, rho);

    polyvecl_ntt(&z);
    polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    poly_ntt(&cp);
    polyveck_shiftl(&t1);
    polyveck_ntt(&t1);
    polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

    polyveck_sub(&w1, &w1, &t1);
    polyveck_reduce(&w1);
    polyveck_invntt_tomont(&w1);

    /* Reconstruct w1 */
    polyveck_caddq(&w1);
    polyveck_use_hint(&w1, &w1, &h);
    polyveck_pack_w1(buf, &w1);

    /* Call random oracle and verify challenge */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, SEEDBYTES, &state);
    shake256_inc_ctx_release(&state);
    for (i = 0; i < SEEDBYTES; ++i) {{
        if (c[i] != c2[i]) {{
            return -1;
        }}
    }}

    return 0;
}}
"""

            with open(f"extern/dilithium{level}/{impl}/sign.c", 'w') as h_file:
                h_file.write(template)

if __name__ == "__main__":
    main()
