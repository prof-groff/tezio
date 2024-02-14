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

#ifndef BIP39_H
#define BIP39_H

#include <Arduino.h>
#include "sha2.h"
#include "pbkdf2.h"

uint16_t word_to_index(const char* myword);
uint16_t mnemonic_to_entropy(char mnemonic[][10], uint16_t n_words, uint8_t entropy[]);
uint16_t entropy_to_mnemonic(uint8_t entropy[], uint16_t entropy_length, char mnemonic[][10]);
uint16_t mnemonic_to_string(char (*mnemonic)[10], uint16_t n_words, char* mnemonic_string);
uint16_t mnemonic_string_to_array(char *mnemonic_string, uint16_t mnemonic_string_length, char (*mnemonic)[10]);
void mnemonic_string_to_seed(char *mnemonic_string, uint16_t mnemonic_string_length, uint8_t *seed, char *password = NULL, uint16_t password_length = 0, uint16_t iterations = 2048);
uint16_t validate_mnemonic_string(char *mnemonic_string, uint16_t mnemonic_string_length);

#endif