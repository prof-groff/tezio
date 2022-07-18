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

  delay(1000);
  Serial.println("Testing HMAC_SHA-512...");
  uint8_t key[20] = {0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
                   0x0B, 0x0B, 0x0B, 0x0B};
  uint8_t data2[] = "Hi There";
  uint8_t hmac[SHA512_HASH_SIZE];
  hmac_sha512(key, sizeof(key), data2, sizeof(data2)-1, hmac);
  for (uint16_t i = 0; i < SHA512_HASH_SIZE; i++) {
    Serial.print(hmac[i], HEX); Serial.print(' ');
  }
  Serial.println();

}

void loop() {

}