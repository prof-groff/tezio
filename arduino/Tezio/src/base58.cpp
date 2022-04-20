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
#include "base58.h"

size_t base58_func(uint8_t *data, size_t datalen, char *out)
{
    
    const size_t buffersize = 1 + (datalen * 138/100);
    uint8_t buffer[buffersize] = {0};
    uint16_t digits = 1;
    bool flag = false;
    uint16_t zeros = 0;
    
    for (int i = 0; i < datalen; i++) {
        if (!flag && data[i] == 0) {
            zeros++;
        }
        if (!flag && data[i] != 0) {
            flag = true;
        }
        if (flag) {
            uint32_t carry = (uint32_t) data[i];
            for (int j = 0; j < digits; j++) {
                carry += ((uint32_t) buffer[j]) << 8;
                buffer[j] = carry % 58;
                carry = carry / 58;
            }
            while (carry > 0) {
                buffer[digits] = carry % 58;
                digits ++;
                carry = carry/58;
            }
        }
    }
    
    size_t outlen = zeros + digits + 1;
    int k = 0;
    for (; k < zeros;) {
        out[k] = '1'; // zeros mapped to base58 1
        k++;
    }
    for (; k < zeros+digits;) {
        out[k] = base58[buffer[digits-k-1]]; // order of digits reversed
        k++;
    }
    out[k] = '\0';
    return outlen;
  
}
