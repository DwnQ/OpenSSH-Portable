#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define gen_matrix KYBER_NAMESPACE(gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
#define indcpa_keypair KYBER_NAMESPACE(indcpa_keypair)
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

#define indcpa_enc KYBER_NAMESPACE(indcpa_enc)
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

#define indcpa_dec KYBER_NAMESPACE(indcpa_dec)
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);

//----------------------------------Modified--------------------------------------------
#define aes_gcm_256b_encrypt KYBER_NAMESPACE(aes_gcm_256b_encrypt)
int aes_gcm_256b_encrypt(uint8_t  *plaintext,
                         size_t    plaintext_len,
                         char  *skey,
                         uint8_t  *aad,
                         size_t    aad_len,
                         uint8_t **iv,
                         uint8_t  *iv_len,
                         uint8_t **tag,
                         uint8_t  *tag_len,
                         uint8_t **ciphertext,
                         uint8_t  *ciphertext_len);
#define aes_gcm_256b_decrypt KYBER_NAMESPACE(aes_gcm_256b_decrypt)
int aes_gcm_256b_decrypt(uint8_t  *ciphertext,
                         size_t    ciphertext_len,
                         char  *skey,
                         uint8_t  *aad,
                         size_t    aad_len,
                         uint8_t  *iv,
                         uint8_t   iv_len,
                         uint8_t  *tag,
                         size_t    tag_len,
                         uint8_t **plaintext,
                         uint8_t  *plaintext_len);
#define indcpa_keypair_attack KYBER_NAMESPACE(indcpa_keypair_attack)
void indcpa_keypair_attack(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);
#define generate_sk_attack KYBER_NAMESPACE(generate_sk_attack)
void generate_sk_attack(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);
//----------------------------------End-Modified--------------------------------------------

#endif
