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
#include "ateccx08_configuration.h"

Cryptochip myChip(Wire, 0x60);

void setup() {
  start_serial();
  Serial.println("-- Tezio Wallet Configuration Sketch --"); Serial.println(); delay(1000);
  Serial.println("Attempting to write configuration data to cryptographic co-processor."); delay(1000);

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
    if (!myChip.writeConfiguration(CRYPTOCHIP_CONFIG)) {
      Serial.println("Error: Failed to write configuration data.");
      wait_forever();
    }
    else {
      Serial.println("Configuration data successfully written to device."); delay(1000);
    }
  }
  else if (lock_status[1] == 1) {
    Serial.println("The cryptographic co-processor's configuration data is already locked. New configuration data can not be written."); delay(1000);
  }

  uint8_t config_data[128];
  Serial.println("Attempting to read and print current configuration data."); delay(1000);
  if (!myChip.readConfiguration(config_data)) {
    Serial.println("Error: Failed to read configuration data.");
    wait_forever();
  }
  else {
    print_hex_data(config_data, sizeof(config_data)); delay(1000);
  }

  if (lock_status[1] == 0) {
    Serial.println("Do you wish to lock the configuration data zone?"); 
    if (confirm_entry()) {
      if (!myChip.lockConfigZone()) {
        Serial.println("Error: Failed to lock the configuration zone.");
        wait_forever();
      }
      else {
        Serial.println("Configuration zone locked successfully.");
        wait_forever(); // done
        }
      }
    else {
      Serial.println("Configuration zone remains unlocked. It must be locked before use.");
      wait_forever();
    }
  }

  

}

void loop() {
  
}
