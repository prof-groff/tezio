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

#include <Arduino.h>
#include "bip32.h"
#include "sha2.h"
#include "hmac.h"

uint16_t path_preprocess(char *path, uint16_t path_length) {
  uint16_t n_indeces = 0;
  for (uint16_t i = 0; i < path_length; i++) {
    if (path[i] == '/') {
      n_indeces++;
    }
  }

  return n_indeces;
}

void path_to_indeces(char *path, uint16_t path_length, uint32_t *indeces, uint16_t n_indeces) {
  bool active = false;
  uint16_t counter = 0;
  uint32_t index = 0;
  for (uint16_t i = 0; i < path_length; i++) {
    if (path[i] == '/' && active) { // end of index
      indeces[counter] = index; // save current index
      counter++; // increment counter
      index = 0; // reset index
    }
    else if (path[i] == '/' && !active) {
      active = true; // beginning first index
    }
    else if (active) {
      if (path[i] == '\'') {
        index += (uint32_t(1) << 31); // hardened
      }
      else {
        index = index * 10 + (path[i] - '0');
      }
    }
    else {
      // do nothing
    }
  }
  indeces[counter] = index;
}

void child_skcc(uint8_t *parent_skcc, uint32_t index, uint8_t *hmac) {

  uint8_t parent_sk[32];
  uint8_t parent_cc[32];
  memcpy(parent_sk, parent_skcc, 32); // first half
  memcpy(parent_cc, &parent_skcc[32], 32); // second half
  
  uint8_t data[1 + 32 + 4]; // prefix byte 0x00 + parent_sk + index (4 bytes)

  uint8_t index_bytes[4];
  memset(index_bytes, 0, 4);
  for (uint8_t i = 4; i > 0; i--) { // count backward, convert uint32_t to bigendian uint8_t array
    index_bytes[i-1] = (uint8_t)index;
    index = index >> 8;
  }

  // copy parts to data
  data[0] = 0x00;
  memcpy(&data[1], parent_sk, 32);
  memcpy(&data[1+32], index_bytes, 4);

  hmac_sha512(parent_cc, 32, data, sizeof(data), hmac);

}
