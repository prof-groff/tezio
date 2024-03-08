/* MIT License

Copyright (c) 2024 Jeffrey R. Groff

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

#ifndef CONSTANTS_H
#define CONSTANTS_H

#define SHORTWAIT 1000

// CURVES and PUBLIC KEY HASH ALIASES
#define NISTP256_AUTH 0
#define ED25519 1
#define SECP256K1 2
#define NISTP256 3

#define TZ3_AUTH 0
#define TZ1 1
#define TZ2 2
#define TZ3 3

// MEMORY SLOTS ON THE HSM TO USE FOR SECRET KEYS 
#define P2_AUTH_KEY_SLOT 0 // 0, slot for authentication key
#define P2_SK_SLOT 3 // slot for NIST P256 secret key, must be between 0 and 3 using default cryptochip configuration.
#define SP_SK_SLOT 4 // slot for secp256k1 secret key, must be between 4 and 7 using default cryptochip configuration.
#define ED_SK_SLOT 5 // slot for ed25519 secret key, must be between 4 and 7 using default cryptochip configuration.

// MEMORY SLOTS ON THE HSM TO STORE PUBLIC KEYS
// (public keys can also be derived from secret/private keys)
// must be between 11 and 14 using default cryptochip configuration.
#define P2_PK_SLOT 11
#define SP_PK_SLOT 12
#define ED_PK_SLOT 13
#define P2_AUTH_KEY_PK_SLOT 14 // 14, slot for authentication public key

// MEMORY SLOT ON THE HSM TO STORE THE KEY FOR ENCRYPTED READS/WRITES
// must be 10 using default cryptochip configuration.
#define RW_KEY_SLOT 10

// other stuff
#define ED_PK_SIZE 32
#define SP_PK_SIZE 64
#define P2_PK_SIZE 64

#define PKH_SIZE 20

#define SK_SIZE 32

// curve orders n (maximum value allowed for valid key is n-1)
const uint8_t n_sp[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 
                           0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 
                           0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}; // secp256k1
    
const uint8_t n_p2[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
                          0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51}; // nist p256 (secp256r1)


const uint8_t n_sp_div2[32] = {0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
							   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
							   0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
							   0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0}; // n_sp >> 1

const char sp_hmac_key[] = "Bitcoin seed";
const char p2_hmac_key[] = "Nist256p1 seed";
const char ed_hmac_key[] = "ed25519 seed";

const uint8_t TZ1_PREFIX[3] = {0x06, 0xA1, 0x9F}; // tz1
const uint8_t TZ2_PREFIX[3] = {0x06, 0xA1, 0xA1}; // tz2
const uint8_t TZ3_PREFIX[3] = {0x06, 0xA1, 0xA4}; // tz3

const uint8_t TZ1_PK[4] = {0x0D, 0x0F, 0x25, 0xD9}; // edpk
const uint8_t TZ2_PK[4] = {0x03, 0xFE, 0xE2, 0x56}; // sppk
const uint8_t TZ3_PK[4] = {0x03, 0xB2, 0x8B, 0x7F}; // p2pk

const uint8_t TZ1_SIG[5] = {0x09, 0xF5, 0xCD, 0x86, 0x12}; // edsig
const uint8_t TZ2_SIG[5] = {0x0D, 0x73, 0x65, 0x13, 0x3F}; // spsig
const uint8_t TZ3_SIG[4] = {0x36, 0xF0, 0x2C, 0x34}; // p2sig
const uint8_t DEF_SIG[3] = {0x04, 0x82, 0x2B}; // default sig 

// prefixes for base58 encoded secret keys
const uint8_t TZ1_SKPK[4] = {0x2B, 0xF6, 0x4E, 0x07}; // edsk (version with public key appended)
const uint8_t TZ1_SK[4] = {0x0D, 0x0F, 0x3A, 0x07}; // edsk
const uint8_t TZ2_SK[4] = {0x11, 0xA2, 0xE0, 0xC9}; // spsk
const uint8_t TZ3_SK[4] = {0x10, 0x51, 0xEE, 0xBD}; // p2sk

		


#endif