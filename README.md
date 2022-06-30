# Tezio Wallet

An open-source hardware wallet built for the Arduino MKR WIFI 1010 and Nano 33 IoT. To run the wallet the board must first be configured and provisioned. Example sketches are included. All interactions with the <code>configure</code>, <code>random_bytes</code>, and <code>provision</code> sketches are done via the Arduino IDE serial monitor. Once the board is configured and provisioned, upload the <code>run</code> sketch and interact via the API. 

## Example Sketches

### <code>configure</code>

The configuration zone of the ATECCX08 cryptographic coprocessors on the Arduino boards must first be written and locked before cryptographic processes can be executed. The <code>configure.ino</code> sketch is accompanied by <code>ateccx08_configure.h</code> containing the default configuration data. 

### <code>random_bytes</code>

Once the configuration zone is locked this sketch can be used to generate random 32-byte keys using the true random number generator on the ATECCX08 cryptographic coprocessor. These 

### <code>provision</code>

This sketch writes secret keys to the ATECCX08 data zone and locks the device. The <code>SECRETS.h</code> file contains the keys and should not be shared with anyone or published to any publicly accessible device. To recover a previously created wallet, include the 24-word recovery phrase in <code>SECRETS.h</code>. Otherwise, a new 24-word recovery phrase will be generated when the sketch is run. Write this down and keep it safe. By default, the recovery phrase is used to generate ECC public/private key pairs for the secp256k1 curve using BIP-0032 (results in tz2 address) and the NIST P-256 curve and ed25519 curve using SLIP-0010 (results in tz3 and tz1 addresses, respectively). Once generated the keys are written to the ATECCX08 for future use. The secp256k1 and ed25519 private keys can be read from the device but are encrypted using the read/write key specified in the <code>SECRETS.h</code> file. However, the P-256 private key is written to the device and can never be read. It is stored in the ATECCX08Õs secure element and never has to be read because the chip can carry out cryptographic functions include message signing, message verification, and public key derivation in hardware. 

### <code>run</code>

SKETCH TO IMPLEMENT THE API TO INTERACT WITH THE WALLET. WORK IN PROGRESS. 

[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)

