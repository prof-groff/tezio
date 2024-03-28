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

#include <TezioHSM_Provision.h>
#include "provision_secrets.h"
#include "configuration.h"

/* Upload and run this sketch to configure Tezio Wallet on an Arduino WiFi 1010 or Arduino Nano 33 IoT.

The readWriteKey below can be set to any 32-byte value but the same key must be used with both the Tezio_Wallet_Setup and the Tezio_Wallet_API sketches.  

This key is stored in the cyptographic coprocessor and used by the system to perform encrypted reads and writes into slots on the cryptochip for which this functionality is enabled. Once this key is written to the device it can be changed via an ecrypted write (if the current value is known) but can never be read. It should not be shared. */



void setup() {
  start_serial();

  TezioHSM_Provision myWallet;

  if (!myWallet.configure(CryptochipConfiguration)) {
    Serial.println("Failed to write configuration data to cryptochip."); wait_forever();
  }
  if (!myWallet.check_mnemonic(mnemonic, sizeof(mnemonic))) {
    Serial.println("Mnemonic phrase is not valid."); wait_forever();
  }
  if (!myWallet.derive_keys(path, sizeof(path), password, sizeof(password))) {
    Serial.println("Failed to derive keys from mnemonic."); wait_forever();
  }
  if (!myWallet.provision(readWriteKey, authSecretKey)) {
    Serial.println("Failed to write keys to cryptochip."); wait_forever();
  }
 
}

void loop() {
  delay(100); // do nothing
}
