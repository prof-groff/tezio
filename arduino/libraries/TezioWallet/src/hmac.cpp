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

#include "hmac.h"
#include "sha2.h"
#include <Arduino.h>

void hmac_sha512(uint8_t *key, uint16_t key_length, uint8_t *txt, uint16_t txt_length, uint8_t *out)
{

  uint8_t outer[SHA512_BLOCK_SIZE + SHA512_HASH_SIZE];
  uint8_t inner[SHA512_BLOCK_SIZE + txt_length];

  uint8_t hash_output[SHA512_HASH_SIZE];

  // generate hash key, K_0
  memset(outer, 0, SHA512_BLOCK_SIZE + SHA512_HASH_SIZE);
  memset(inner, 0, SHA512_BLOCK_SIZE + txt_length);

  // copy key to inner and outer
  if (key_length > SHA512_BLOCK_SIZE) { // key is longer than block length so hash to get fewer bytes

    sha512_func(key, key_length, hash_output);
    
    memcpy(outer, hash_output, SHA512_HASH_SIZE);
    memcpy(inner, hash_output, SHA512_HASH_SIZE);
  }
  else {
    memcpy(outer, key, key_length);
    memcpy(inner, key, key_length);
  }
  
  // XOR inner and outer with special bytes
  for (uint16_t i = 0; i < SHA512_BLOCK_SIZE; i++) {
    outer[i] ^= 0x5c;
    inner[i] ^= 0x36;
  }

  // concatenate text to inner
  memcpy(inner + SHA512_BLOCK_SIZE, txt, txt_length);

  // hash inner and concatenate to outer
  sha512_func(inner, SHA512_BLOCK_SIZE + txt_length, hash_output);
  memcpy(outer + SHA512_BLOCK_SIZE, hash_output, SHA512_HASH_SIZE);

  // hash outer
  sha512_func(outer, SHA512_BLOCK_SIZE + SHA512_HASH_SIZE, hash_output);
  memcpy(out, hash_output, SHA512_HASH_SIZE);

}
