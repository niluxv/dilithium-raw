#ifndef PQCLEAN_DILITHIUM3_CLEAN_PARAMS_H
#define PQCLEAN_DILITHIUM3_CLEAN_PARAMS_H

#define CRYPTO_NAMESPACE(s) PQCLEAN_DILITHIUM3_CLEAN_##s
#define DILITHIUM_NAMESPACE(s) CRYPTO_NAMESPACE(s)

#define SEEDBYTES 32
#define CRHBYTES 64
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

#define K 6
#define L 5
#define ETA 4
#define TAU 49
#define BETA 196
#define GAMMA1 (1 << 19)
#define GAMMA2 ((Q-1)/32)
#define OMEGA 55
#define PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_ALGNAME "Dilithium3"


#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (OMEGA + K)

#define POLYZ_PACKEDBYTES   640

#define POLYW1_PACKEDBYTES  128

#define POLYETA_PACKEDBYTES 128

#define PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K*POLYT1_PACKEDBYTES)
#define PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES (3*SEEDBYTES \
        + L*POLYETA_PACKEDBYTES \
        + K*POLYETA_PACKEDBYTES \
        + K*POLYT0_PACKEDBYTES)
#define PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES (SEEDBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

#endif
