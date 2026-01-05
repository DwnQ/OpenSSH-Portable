# Timing Analysis of Algorithm Substitution Attacks in a Post-Quantum TLS Protocol

## Overview

This repository implements Algorithm Substitution Attacks on Kyber and Falcon. Its purpose is to evaluate academic research, thus it is not recommended to be used in a production environment. **Use it at your own risk**.

## Installation

Clone this repository:
```
git clone --single-branch --branch asa_in_tls_paper https://github.com/DuniaMarchiori/liboqs.git
```

Run installation script:
``` 
./install.sh
```
If you want to integrate the Falcon attacked version with [OQS-OpenSSL](https://github.com/open-quantum-safe/openssl), run the integration script (only run this after the installation script):
```
./integrate_openssl.sh
```

### Individual branches

This branch contains the implementation of our two algorithm substitution attacks. The Falcon attack can be found individually in the branch `falcon_asa_attack` and the Kyber attack can be found in `kyber_asa_attack`.


## Third Party Repositories

In our Falcon attack we use the Elliptic Curve Integrated Encryption Scheme (ECIES) to establish a shared symmetric key from the attacker public key and an ephemeral key pair, both are ECDH keys.

To implement this scheme, we rely on the fork of a third party library, CECIES. 

The fork made by us can be found [here](https://github.com/JPADN/cecies/tree/asa_falcon) and the library [here](https://github.com/GlitchedPolygons/cecies).


## Testing

The test scripts are located in `build/tests`.

To execute a test, from the build directory run:
```
./tests/<test_name>
```

There are tests provided by liboqs and tests specifically for our ASA attacks, which are the following:
- test_parse_falcon
- test_attack_falcon
- test_attack_falcon1024


### Test: test_parse_falcon

Since the falcon attack require at least 2 signatures to leak secret data, the attacker needs to know how to recognize if the signature he is capturing is the first one or the second one.

To do this we set 2 fixed bits in the AES Initiliazation Vector, such that the first signature has the first bit equal to zero, and the second signature has the first bit equal to 1.

In this script we demonstrate the attacker recognizing this pattern and acting as a state machine, described in `state_machine_falcon_attacker.png`.

The user will be prompted the following:
- Generate a new key pair
- Sign without the attacker capturing
- Sign with the attacker capturing

With these actions, the user can interact with the attacker state machine.

### Test: test_attack_falcon

This script simply performs the algorithm substitution attack on Falcon 512.


It is performed:
- Victim generates a keypair
- Victim signs 2 times
- Attacker captures both signatures
- Attacker parse ciphertext from the signature
- Attacker decrypt ciphertext 
- Attacker recover victim private key

### Test: test_attack_falcon1024

Same as `test_attack_falcon`, but with the Falcon 1024 version.

## Attacks

### Falcon ASA flow

- Victim generates a keypair from a random secret seed
- The malicious implementation will perform an ECIES key establishment with the attacker public key and an ephemeral key pair. Afterwards it will:
    - Encrypt the seed with the key derived from the ECIES shared secret
    - Inject the ciphertext on the victim's signatures
- The attacker will capture two consecutive signatures, and then:
    - Recover the ciphertext 
    - Decrypt the ciphertext, recovering the seed
    - Compute the victim's private key from the secret seed

### Kyber ASA flow
- Victim generates a keypair from a random secret seed
	- The malicious implementation adds information about the secret seed into the public key. The information is encrypted using
	the attacker's symmetric key
- The attacker can recover the secret seed from the public key and reconstruct the private key


## Mininet testing

`mininet_TLStest_script.py`
