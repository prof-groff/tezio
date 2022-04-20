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

#include "Tezio.h"
#include <Arduino.h>

#if defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT)
#include <ArduinoECCX08.h>
#endif

#define MNEMONIC_LENGTH 24


void TezioWallet::store_mnemonic(const char* mnemonic[]) {
    char (*p)[10] = secret_mnemonic; // pointer
    for (uint16_t i = 0; i < MNEMONIC_LENGTH; i++) {
        strcpy(*p++, mnemonic[i]);
    }
    secret_mnemonic_string_length = mnemonic2string(secret_mnemonic, MNEMONIC_LENGTH, secret_mnemonic_string);
}

void TezioWallet::store_entropy(const uint8_t* entropy) {
    memcpy(secret_entropy, entropy, 32);
}

void TezioWallet::store_deriv_path(const char* path, uint16_t path_length) {
    deriv_path_length = path_length;
    deriv_path = (char*)malloc(deriv_path_length);
    strcpy(deriv_path, path);
    
}

void TezioWallet::generate_entropy() {
    #if defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT)
    ECCX08.random(secret_entropy, sizeof(secret_entropy));
    #else
    randomSeed(analogRead(0)); // try to get some randomness from the system
    for (uint16_t i = 0; i < sizeof(secret_entropy); i ++) {
        secret_entropy[i] = random(0, 256); 
    }
    #endif
}

void TezioWallet::generate_mnemonic_from_entropy() {
    entropy2mnemonic(secret_entropy, secret_mnemonic);
    secret_mnemonic_string_length = mnemonic2string(secret_mnemonic, MNEMONIC_LENGTH, secret_mnemonic_string);
}

void TezioWallet::generate_master_seed() {
    uint8_t salt[] = "mnemonic";
    uint16_t c = 2048;
    uint8_t mnemonic_string_bytes[secret_mnemonic_string_length]; // convert mnemonic string from char to uint8_t
    memcpy(mnemonic_string_bytes, secret_mnemonic_string, secret_mnemonic_string_length);
    pbkdf2_hmac_sha512(mnemonic_string_bytes, secret_mnemonic_string_length - 1, salt, sizeof(salt) - 1, c, MASTER_SEED_SIZE, secret_master_seed);
}

void TezioWallet::generate_master_secret_key_and_chain_code() {
    uint8_t key[] = "ed25519 seed";
    hmac_sha512(key, sizeof(key)-1, secret_master_seed, MASTER_SEED_SIZE, master_skcc);
}

void TezioWallet::generate_child_secret_key_and_chain_code() {
    uint16_t n_indeces;
    n_indeces = path_preprocess(deriv_path, deriv_path_length - 1);
    uint32_t indeces[n_indeces];
    path_to_indeces(deriv_path, deriv_path_length - 1, indeces, n_indeces);
    uint8_t parent_skcc[64];
    memcpy(child_skcc, master_skcc, 64); // copy master sk cc to child sk cc
    for (uint16_t i = 0; i < n_indeces; i++) {
        memcpy(parent_skcc, child_skcc, 64); // copy previous child to parent
        child_skcc_func(parent_skcc, indeces[i], child_skcc);
    } 
}

void TezioWallet::generate_public_key_ed25519() {
    uint8_t sk[32];
    memcpy(sk, child_skcc, 32); // first 32 bytes
    Ed25519::derivePublicKey(public_key,  sk);
}

void TezioWallet::generate_public_key_hash() {
    BLAKE2b blake2b; 
    uint8_t pkhash[20];
    blake2b.reset(20);
    blake2b.update(public_key, sizeof(public_key));
    blake2b.finalize(pkhash, 20);
    uint8_t prefix[3] = {0x06, 0xa1, 0x9f};
    uint8_t tzpkhash[3 + sizeof(pkhash)];
    memcpy(&tzpkhash[0], &prefix[0], 3);
    memcpy(&tzpkhash[3], &pkhash[0], sizeof(pkhash));
    uint8_t sha256a[32];
    uint8_t sha256b[32]; // apply sha256 twice
    sha256_func(tzpkhash, 23, sha256a);
    delay(100);
    sha256_func(sha256a, 32, sha256b);
    uint8_t tzaddress[27];
    memcpy(&tzaddress[0], &tzpkhash[0], 23);
    memcpy(&tzaddress[23], &sha256b[0], 4);
    memset(public_key_hash, '\0', sizeof(public_key_hash));
    size_t outlength = base58_func(tzaddress, sizeof(tzaddress), public_key_hash);

}

void TezioWallet::generate_entropy_from_mnemonic() {
    mnemonic2entropy(secret_entropy, secret_mnemonic);   
}

void TezioWallet::generate_tz_address(const char path[], uint16_t path_length) {
    generate_master_seed();
    generate_master_secret_key_and_chain_code();
    store_deriv_path(path, path_length);
    generate_child_secret_key_and_chain_code();
    generate_public_key_ed25519();
    generate_public_key_hash();
}


TezioWallet::TezioWallet(const char path[], uint16_t path_length) {
    generate_entropy();
    generate_mnemonic_from_entropy();
    generate_tz_address(path, path_length);
}


TezioWallet::TezioWallet(const uint8_t *entropy, const char path[], uint16_t path_length) {
    store_entropy(entropy);
    generate_mnemonic_from_entropy();
    generate_tz_address(path, path_length);
    
}

TezioWallet::TezioWallet(const char* mnemonic[], const char path[], uint16_t path_length) {
    store_mnemonic(mnemonic);
    generate_entropy_from_mnemonic();
    generate_tz_address(path, path_length);
}