#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"
#include "symmetric.h"
#include <stdint.h>

/*************************************************
* Name:        PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair
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
) {
    uint8_t tr[SEEDBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    rho = random;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    /* Expand matrix */
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_expand(mat, rho);

    /* Sample short vectors s1 and s2 */
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_uniform_eta(&s1, rhoprime, 0);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_uniform_eta(&s2, rhoprime, L);

    /* Matrix-vector multiplication */
    s1hat = s1;
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&s1hat);
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&t1);

    /* Add error vector s2 */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_add(&t1, &t1, &s2);

    /* Extract t1 and write public key */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_caddq(&t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_power2round(&t1, &t0, &t1);
    PQCLEAN_DILITHIUM2_CLEAN_pack_pk(pk, rho, &t1);

    /* Compute H(rho, t1) and write secret key */
    shake256(tr, SEEDBYTES, pk, PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES);
    PQCLEAN_DILITHIUM2_CLEAN_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

    return 0;
}

/*************************************************
* Name:        PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature
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
) {
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
    PQCLEAN_DILITHIUM2_CLEAN_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    /* Compute CRH(tr, msg) */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);

    /* Expand matrix and transform vectors */
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_expand(mat, rho);
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&s1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_ntt(&s2);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_ntt(&t0);

rej:
    /* Sample intermediate vector y */
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    /* Matrix-vector multiplication */
    z = y;
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&w1);

    /* Decompose w and call the random oracle */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_decompose(&w1, &w0, &w1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_pack_w1(sig, &w1);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, sig, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, SEEDBYTES, &state);
    shake256_inc_ctx_release(&state);
    PQCLEAN_DILITHIUM2_CLEAN_poly_challenge(&cp, sig);
    PQCLEAN_DILITHIUM2_CLEAN_poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_invntt_tomont(&z);
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_add(&z, &z, &y);
    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_reduce(&z);
    if (PQCLEAN_DILITHIUM2_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        goto rej;
    }

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_sub(&w0, &w0, &h);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&w0);
    if (PQCLEAN_DILITHIUM2_CLEAN_polyveck_chknorm(&w0, GAMMA2 - BETA)) {
        goto rej;
    }

    /* Compute hints for w1 */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&h);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&h);
    if (PQCLEAN_DILITHIUM2_CLEAN_polyveck_chknorm(&h, GAMMA2)) {
        goto rej;
    }

    PQCLEAN_DILITHIUM2_CLEAN_polyveck_add(&w0, &w0, &h);
    n = PQCLEAN_DILITHIUM2_CLEAN_polyveck_make_hint(&h, &w0, &w1);
    if (n > OMEGA) {
        goto rej;
    }

    /* Write signature */
    PQCLEAN_DILITHIUM2_CLEAN_pack_sig(sig, sig, &z, &h);
    return 0;
}

/*************************************************
* Name:        PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify
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
) {
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

    PQCLEAN_DILITHIUM2_CLEAN_unpack_pk(rho, &t1, pk);
    if (PQCLEAN_DILITHIUM2_CLEAN_unpack_sig(c, &z, &h, sig)) {
        return -1;
    }
    if (PQCLEAN_DILITHIUM2_CLEAN_polyvecl_chknorm(&z, GAMMA1 - BETA)) {
        return -1;
    }

    /* Compute CRH(H(rho, t1), msg) */
    shake256(mu, SEEDBYTES, pk, PQCLEAN_DILITHIUM2_CLEAN_CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, SEEDBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    /* Matrix-vector multiplication; compute Az - c2^dt1 */
    PQCLEAN_DILITHIUM2_CLEAN_poly_challenge(&cp, c);
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_expand(mat, rho);

    PQCLEAN_DILITHIUM2_CLEAN_polyvecl_ntt(&z);
    PQCLEAN_DILITHIUM2_CLEAN_polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

    PQCLEAN_DILITHIUM2_CLEAN_poly_ntt(&cp);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_shiftl(&t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_ntt(&t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

    PQCLEAN_DILITHIUM2_CLEAN_polyveck_sub(&w1, &w1, &t1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_reduce(&w1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_invntt_tomont(&w1);

    /* Reconstruct w1 */
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_caddq(&w1);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_use_hint(&w1, &w1, &h);
    PQCLEAN_DILITHIUM2_CLEAN_polyveck_pack_w1(buf, &w1);

    /* Call random oracle and verify PQCLEAN_DILITHIUM2_CLEAN_challenge */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, SEEDBYTES, &state);
    shake256_inc_ctx_release(&state);
    for (i = 0; i < SEEDBYTES; ++i) {
        if (c[i] != c2[i]) {
            return -1;
        }
    }

    return 0;
}
