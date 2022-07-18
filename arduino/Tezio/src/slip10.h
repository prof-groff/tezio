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

#ifndef SLIP10_H
#define SLIP10_H

#include <Arduino.h>
#include "constants.h"
#include "crypto_helpers.h"
#include "hmac.h"

void seed_to_master_skcc(char *seed, uint16_t seed_length, uint8_t *master_skcc, uint8_t curve); 
void seed_to_master_skcc(uint8_t *seed, uint16_t seed_length, uint8_t *master_skcc, uint8_t curve);
void master_skcc_to_child_sk(uint8_t *master_skcc, char *path, uint16_t path_length, uint8_t *child_sk, uint8_t curve); 
void master_skcc_to_child_sk(uint8_t *master_skcc, char *path, uint16_t path_length, char *child_sk, uint8_t curve); 
uint16_t derivation_path_preprocess(char *path, uint16_t path_length);
void derivation_path_to_indeces(char *path, uint16_t path_length, uint32_t *indeces, uint16_t n_indeces);
uint16_t derive_child_skcc_from_parent(uint8_t *parent_skcc, uint32_t index, uint8_t *child_skcc, uint8_t curve);
void finalize_child_skcc(uint8_t *child_skcc, uint8_t *parent_sk, uint8_t curve);
uint16_t child_sk_is_valid(uint8_t *LEFT, uint8_t *child_skcc, uint8_t curve);
uint8_t key_is_valid(uint8_t *sk, uint16_t n_bytes, uint8_t curve);
uint8_t key_not_zero(uint8_t *sk, uint16_t n_bytes);
uint8_t key_less_than_order(uint8_t *sk, const uint8_t *n, uint16_t n_bytes);
void add_bytes_modulo_n(uint8_t *a, uint8_t *b, const uint8_t *n, uint8_t *r, uint16_t n_bytes);

#endif