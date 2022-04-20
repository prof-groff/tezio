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

#include <Arduino.h>
#include "sha2.h"
#include <SHA512.h>

#if defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT)
#include <ArduinoECCX08.h>
#else 
#include <SHA256.h>
#endif

void sha512_func(uint8_t *data, uint16_t data_length, uint8_t *hash_output) {
  SHA512 sha512; // hash object
  SHA512 *hash = &sha512; // pointer to hash object
  
  hash->reset();
  uint16_t _cursor = 0;
  uint16_t current_block_length; 

  uint16_t n_blocks = data_length / SHA512_BLOCK_SIZE; // integer math
  if (data_length % SHA512_BLOCK_SIZE) {
    n_blocks++;
  }
  for (uint16_t i = 0; i < n_blocks; i++) {
    current_block_length = min(SHA512_BLOCK_SIZE, data_length - _cursor);
    hash->update(data+_cursor, current_block_length);
    _cursor += current_block_length;
  }
  hash->finalize(hash_output, SHA512_HASH_SIZE);
  return;
}

#if defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT)

void sha256_func(uint8_t *data, uint16_t data_length, uint8_t *hash_output) {
    ECCX08.beginSHA256();
    uint16_t _cursor = 0;
    uint16_t current_block_length;
    uint8_t chunk[SHA256_BLOCK_SIZE];
    uint16_t n_blocks = data_length / SHA256_BLOCK_SIZE; // integer math
    if (data_length % SHA256_BLOCK_SIZE) {
      n_blocks++;
    }
    for (uint16_t i = 0; i < n_blocks; i++) {
      current_block_length = min(SHA256_BLOCK_SIZE, data_length - _cursor);
      memcpy(chunk, &data[_cursor], current_block_length);
      if (current_block_length == SHA256_BLOCK_SIZE) { // full block
        ECCX08.updateSHA256(chunk);
      }
      else { // partial block, end
        ECCX08.endSHA256(chunk, current_block_length, hash_output);
      }
      _cursor += current_block_length;
    }
}

#else

void sha256_func(uint8_t *data, uint16_t data_length, uint8_t *hash_output) {
  SHA256 sha256; // hash object
  SHA256 *hash = &sha256; // pointer to hash object
  
  hash->reset();
  uint16_t _cursor = 0;
  uint16_t current_block_length; 

  uint16_t n_blocks = data_length / SHA256_BLOCK_SIZE; // integer math
  if (data_length % SHA256_BLOCK_SIZE) {
    n_blocks++;
  }
  for (uint16_t i = 0; i < n_blocks; i++) {
    current_block_length = min(SHA256_BLOCK_SIZE, data_length - _cursor);
    hash->update(data+_cursor, current_block_length);
    _cursor += current_block_length;
  }
  hash->finalize(hash_output, SHA256_HASH_SIZE);
  return;
}

#endif
