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

#ifndef SHA2_H
#define SHA2_H

#include <Arduino.h>
#include <SHA512.h>

#define SHA512_HASH_SIZE 64
#define SHA512_BLOCK_SIZE 128
#define SHA256_HASH_SIZE 32
#define SHA256_BLOCK_SIZE 64

void sha512_func(uint8_t *data, uint16_t data_length, uint8_t *hash_output);
void sha256_func(uint8_t *data, uint16_t data_length, uint8_t *hash_output);
void sha256_func_host(uint8_t *data, uint16_t data_length, uint8_t *hash_output);

#endif