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

uint8_t ct_attack[INFOATTACK];  // Info saved from the signatures
int state;  // Attacker state

int attacker_parse(uint8_t *sig) {
  if (sig[0+1] < 0x80) {
    printf("Este é o primeiro ciphertext\n");  
    memcpy(ct_attack, sig + 1, 40);
    state = 1;
  } else {    
    printf("Este é o segundo ciphertext\n");
    if (state == 1) {
      memcpy(ct_attack+40, sig + 1, 40);
      state = 2;
      return 1;
    }
  }
  return 0;
}

// Decrypt info in ct_attack
int attacker_decrypt(uint8_t** plaintext_dec) {
    size_t plaintext_len;

    cecies_curve25519_key private_key = {.hexstring = "48bddcca7d36729e0f54acedf7016b14c72423749757fc80d90d9017fea3cbc0"};

    if (cecies_curve25519_decrypt(ct_attack, INFOATTACK, 0, private_key, plaintext_dec, &plaintext_len)) {
      printf("cecies_curve25519_decrypt failed\n");
      return 1;
    }
    return 0;
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

    // Generating first keypair
    ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
    if (ret != 0) {
        printf("ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair failed\n");
    }
    
    int question, error;
    
    printf("Choose an option:\n");
    
    while (1) {
      printf("Generate new key (1)\nSign without attacker capturing (2)\nSign with Attacker capturing (3)\n");
      scanf("%d", &question);

      if (question == 1) {
        ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk); // Overwriting pk,sk... Is this ok?
        state = 0;
        if (ret != 0) {
            printf("ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair failed\n");
        }
      } else {
        ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, &siglen, message, MESSAGELEN, sk);
        if (ret != 0) {
          printf("ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign failed\n");
        }

        ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, message, MESSAGELEN, pk);
        if (ret != 0) {
          printf("ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign_verify failed\n");
        }
        
        if (question == 3) {
          if (attacker_parse(sig)) {
            ret = attacker_decrypt(&plaintext_dec);
            if (ret != 0) {
              printf("ERROR: Decryption failed\n");
              state = 0;
            }
            
            ret = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_attack(generated_sk, plaintext_dec);
            
            if (ret != 0) {
              printf("ERROR: PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_attack failed\n");
              state = 0;
            }


            // Uncomment this to print out the original private key
            // for (int i = 0; i < OQS_SIG_falcon_512_length_secret_key; ++i) {
            //   printf("%02x", sk[i]);
            // }
            // printf("\n\n");
            
            
            error = 0;
            // Check if the generated private key is equal to the original private key
            for (int i = 0; i < OQS_SIG_falcon_512_length_secret_key; ++i) {
              // Uncomment this to print out the generated private key (from the attack)
              // printf("%02x", generated_sk[i]);
              
              if (generated_sk[i] != sk[i]) {
                printf("wrong sk in index %d\n", i);
                error = 1;
              }
            }
            if (!error) {
              printf("Attack Sucessful\n");
              break;
            }
            else {
              printf("Attack Failed\n");
              state = 0;
            }
          }
        }
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