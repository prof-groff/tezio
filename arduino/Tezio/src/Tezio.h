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
#include "bip32.h"
#include "pbkdf2.h"
#include "bip39.h"
#include <Arduino.h>
#include <Ed25519.h>
#include <BLAKE2b.h>

#define ENTROPY_SIZE 32
#define MASTER_SEED_SIZE 64

class TezioWallet {
    
    private:
    
        uint8_t secret_entropy[ENTROPY_SIZE];
        char secret_mnemonic[24][10]; // maximum length of words in the vocab is 9, so 10 including null character
        char secret_mnemonic_string[24*10]; // phrase as one long string
        uint16_t secret_mnemonic_string_length;
        uint8_t secret_master_seed[MASTER_SEED_SIZE];
        uint8_t master_skcc[64];
        uint8_t child_skcc[64];
        char *deriv_path;
        uint16_t deriv_path_length;
    
        void store_mnemonic(const char* mnemonic[]);
        void store_entropy(const uint8_t* entropy);
        void store_deriv_path(const char* path, uint16_t path_length);
        
        void generate_entropy();
        void generate_mnemonic_from_entropy();
        void generate_master_seed();
        void generate_master_secret_key_and_chain_code();
        void generate_child_secret_key_and_chain_code();
        void generate_public_key_ed25519();
        void generate_public_key_hash(); // tz address
        void generate_entropy_from_mnemonic();
        void generate_tz_address(const char path[], uint16_t path_length);
    
    public:
        
        uint8_t public_key[32];
        char public_key_hash[60];
    
        TezioWallet(const char path[] = "m/44'/1729'/0'/0'", uint16_t path_length = 18);
        TezioWallet(const uint8_t *entropy, const char path[] = "m/44'/1729'/0'/0'", uint16_t path_length = 18);
        TezioWallet(const char* mnemonic[], const char path[] = "m/44'/1729'/0'/0'", uint16_t path_length = 18);
    
};

#endif
