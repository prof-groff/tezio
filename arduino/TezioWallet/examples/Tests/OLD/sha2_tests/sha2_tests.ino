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

#include <Tezio.h>

void setup() {
    
  Serial.begin(9600);
  while (!Serial);

  uint8_t data[3] = {'a', 'b', 'c'};

  delay(1000);
  Serial.println("Testing SHA-256...");
  uint8_t sha256_output[SHA256_HASH_SIZE];
  sha256_func(data, sizeof(data), sha256_output); 
  for (uint16_t i = 0; i < SHA256_HASH_SIZE; i++) {
    Serial.print(sha256_output[i], HEX); Serial.print(' ');
  }
  Serial.println();

  delay(1000);
  Serial.println("Testing SHA-512...");
  uint8_t sha512_output[SHA512_HASH_SIZE];
  sha512_func(data, sizeof(data), sha512_output); 
  for (uint16_t i = 0; i < SHA512_HASH_SIZE; i++) {
    Serial.print(sha512_output[i], HEX); Serial.print(' ');
  }
  Serial.println();

}

void loop() {

}
