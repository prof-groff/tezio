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

Cryptochip myChip(Wire, 0x60);

void setup() {
  start_serial();
  Serial.println("-- Tezio Wallet Random Key Generator --"); Serial.println(); delay(1000);
  
  // detect ATECCX08 chip on connected device
  if(!myChip.begin()) {
    Serial.println("Error: No cryptographic co-processor was detected on the connected device.");
    wait_forever();
  }
 
  // check lock status
  uint8_t lock_status[2];
  if (!myChip.locked(lock_status)) {
    Serial.println("Error: Failed to determine cryptographic co-processor lock status. Configuration data can not be written.");
    wait_forever();
  }


  if (lock_status[1] == 0) {
    Serial.println("Error: The ATECCX08 configuration zone must be locked before the onboard random number generator can be used."); 
    wait_forever();
  }
  else if (lock_status[1] == 1) {
    while(1) {
      uint8_t key[32];
      Serial.println("Do you wish to generate a random 32 byte key?");
      if(confirm_entry()) {
        if (!myChip.random(key, sizeof(key))){
          Serial.println("Error: Failed to generate random key.");
          wait_forever();
        }
        else {
          for (int i = 0; i < sizeof(key) - 1; i++) {
            Serial.print("0x"); Serial.print(key[i], HEX); Serial.print(", ");
          }
          Serial.print("0x"); Serial.println(key[sizeof(key) - 1], HEX);
        }
      }
      
    }
   
  }

}

void loop() {
  
}
