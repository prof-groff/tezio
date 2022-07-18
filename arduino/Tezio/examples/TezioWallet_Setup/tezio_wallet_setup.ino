#include <TezioWallet_Setup.h>
#include "secrets.h"
#include "configuration.h"

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
