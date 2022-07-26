#include <TezioWallet_Setup.h>
#include "secrets.h"
#include "configuration.h"

// the read/write key is stored and used by the system to perform encrypted reads and writes into enabled slots.
// this can be changed to any 32 bytes but the same key must be used with both the Tezio_Wallet_Setup and Tezio_Wallet_API sketches.
const uint8_t readWriteKey[32] = {0x93, 0x46, 0x63, 0xE3, 0xD4, 0xB4, 0x24, 0x62, 
                                  0x0B, 0xEA, 0x19, 0x7A, 0x73, 0xAD, 0x10, 0x54, 
                                  0x22, 0xA0, 0x19, 0x1A, 0x87, 0x79, 0xE6, 0x2C, 
                                  0xA4, 0x61, 0x26, 0x63, 0xA3, 0xF0, 0x99, 0xFB};

void setup() {
  start_serial();

  TezioWallet_Setup myWallet;

  if (!myWallet.configure(CryptochipConfiguration)) {
    Serial.println("Failed to write configuration data to cryptochip."); wait_forever();
  }
  if (!myWallet.check_mnemonic(mnemonic, sizeof(mnemonic))) {
    Serial.println("Mnemonic phrase is not valid."); wait_forever();
  }
  if (!myWallet.derive_keys(path, sizeof(path), password, sizeof(password))) {
    Serial.println("Failed to derive keys from mnemonic."); wait_forever();
  }
  if (!myWallet.provision(readWriteKey)) {
    Serial.println("Failed to write keys to cryptochip."); wait_forever();
  }
 
}

void loop() {
  delay(100); // do nothing
}
