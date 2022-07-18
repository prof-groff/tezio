/* MIT License

Copyright (c) 2022 Jeffrey R. Groff

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

#ifndef TEZIO_H
#define TEZIO_H

#include "base58.h"
#include "sha2.h"
#include "hmac.h"
#include "pbkdf2.h"
#include "bip39.h"
#include <Arduino.h>
#include <Ed25519.h>
#include <BLAKE2b.h>
#include "Cryptochip.h"
#include "ui.h"
#include "crypto_helpers.h"
#include <uECC.h>
#include "slip10.h"
#include "constants.h"

#define ENTROPY_SIZE 32
#define MASTER_SEED_SIZE 64

#define ED25519 1
#define SECP256K1 2
#define NISTP256 3

// default memory slots to use for secret/private keys
#define SK_SLOT_NISTP256 3
#define SK_SLOT_SECP256K1 4
#define SK_SLOT_ED25519 5

// default memory slot to use for public keys (public keys can also be derived from secret/private keys)
#define PK_SLOT_NISTP256 11
#define PK_SLOT_SECP256K1 12
#define PK_SLOT_ED25519 13






class TezioWallet {
    
    private:
    

    
    public:
    
        uint8_t secret_entropy[ENTROPY_SIZE];
        char secret_mnemonic[24][10]; // maximum length of words in the vocab is 9, so 10 including null character
        char secret_mnemonic_string[24*10]; // phrase as one long string
        uint16_t secret_mnemonic_string_length;
        uint8_t secret_master_seed[MASTER_SEED_SIZE];
        uint8_t master_skcc[64];
        uint8_t child_skcc[64];
        uint8_t public_key[32];
        uint8_t public_key_NISTP256[33]; // compressed
        uint8_t public_key_SECP256K1[33]; // compressed
        char public_key_hash[60];
        uint8_t curve;
    
        char *deriv_path;
        uint16_t deriv_path_length;
    
        void store_mnemonic(const char* mnemonic[]);
        void store_mnemonic_from_serial();
        void store_deriv_path(const char* path, uint16_t path_length);
        
        void generate_entropy();
        void generate_mnemonic_from_entropy();
        void generate_master_seed(uint8_t *password = NULL, uint16_t passwordLength = 0);
        void generate_master_secret_key_and_chain_code(uint8_t curve = ED25519);
        void generate_child_secret_key_and_chain_code(uint8_t curve = ED25519);
        void generate_public_key_ed25519();
        void generate_public_key(uint8_t curve = ED25519);
        void generate_public_key_hash(); // tz address
    
        TezioWallet();
        TezioWallet(uint8_t *entropy, const char path[], uint16_t path_length);
        TezioWallet(const char* mnemonic[], const char path[] = "m/44'/1729'/0'/0'", uint16_t path_length = 18);
        TezioWallet(bool Foo, const char path[] = "m/44'/1729'/0'/0'", uint16_t path_length = 18);
    
};

#endif
