#ifndef CRYPTO_HELPERS_H
#define CRYPTO_HELPERS_H

#include <Arduino.h>
#include "constants.h"
#include <Ed25519.h>
#include <uECC.h>
#include <BLAKE2b.h>
#include "sha2.h"
#include "base58.h"
#include "ui.h"
#include "Cryptochip.h"

uint8_t hex_char_to_num(char c);
char num_to_hex_char(uint8_t n);
uint16_t hex_chars_to_byte_array(char *s, uint16_t s_length, uint8_t *ba, uint16_t ba_length);
uint16_t byte_array_to_hex_chars(uint8_t *ba, uint16_t ba_length, char *s, uint16_t s_length);
void chars_to_bytes(const char *c, uint16_t n_chars, uint8_t *b);
void derive_public_key(uint8_t *sk, uint8_t curve, uint8_t *pk); // doesn't use ATECCX08
void generate_entropy(uint8_t *entropy, uint16_t entropy_length); // doesn't use ATECCX08
void compress_public_key(uint8_t *pk, uint curve, uint8_t *cpk);
uint16_t public_key_base58(uint8_t *pk, uint8_t curve, char *pkb58);
void generate_public_key_hash(uint8_t *pk, uint8_t curve, char *pk_hash);
uint16_t encode_public_key(uint8_t *buffer, uint16_t rawKeyLength, uint8_t pkForm, uint8_t curve);
uint16_t secp256k1_sign(uint8_t *hash, uint8_t *sk, uint8_t *signature);
uint16_t ed25519_sign(uint8_t *hash, uint8_t *sk, uint8_t *pk, uint8_t *signature);
uint16_t secp256k1_verify(uint8_t *hash, uint8_t *pk, uint8_t *signature);
bool ed25519_verify(uint8_t *hash, uint8_t *pk, uint8_t *signature);
int RNG(uint8_t *dest, unsigned int size);
uint16_t base58_encode_prefix_checksum(uint8_t *prefix, uint16_t prefixLength, uint8_t *data, uint16_t dataLength, uint8_t *b58str); 
uint16_t base58_decode_prefix_checksum(uint16_t prefixLength, char *b58str, uint16_t b58strLength, uint8_t *data);

#endif