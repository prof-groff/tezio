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
  Serial.println("Testing PBKDF2_HMAC_SHA512...");
  uint8_t pwd[] = "passwordPASSWORDpassword";
  uint8_t salt[] = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
  uint16_t c = 4096;
  uint8_t dk[25];
  pbkdf2_hmac_sha512(pwd, sizeof(pwd) - 1, salt, sizeof(salt) - 1, c, 25, dk);
  for (uint16_t i = 0; i < 25; i++) {
    Serial.print(dk[i], HEX); Serial.print(' ');
  }
  Serial.println();

}

void loop() {

}
