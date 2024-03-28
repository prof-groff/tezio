#ifndef SECRETS_H
#define SECRETS_H

// The following mnemonic will be used to generate a tz1, tz2, and tz3 address and the corresponding 
// public and private (secret) keys according to process outlined in BIP-39, BIP-32, and SLIP-10. 
// Mnemonic phrases of length 12, 15, 18, 21, and 24 are supported. If a mnemonic phrase is not
// provided, char mnemonic[] = "", then a new 24 word mnemonic phrase will be generated and printed 
// to the serial monitor.
char mnemonic[] = "";

// The following secret key (base58 checksum encoded) is used by octez to sign signature requests sent to the TezioHSM, if this
// feature is enabled by the TezioSigner Flask app. The cooresponding public key is used by TezioHSM
// to authenticate signing requests. If no secret key is provided, char authSecretKey[] = "", then a new
// secret key will be generated and printed to the serial monitor so it can be made known to octez.
char authSecretKey[] = ""; 

// The following secret key is given as 32 unencoded bytes and is used by the HSM to both read and 
// write encrypted data. This key must be provided by the user and is used to both provision TezioHSM
// and by the TezioHSM API. 
const uint8_t readWriteKey[32] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};



// Default derivation path for Tezos hierarchical deterministic wallets as described in BIP-44 and SLIP-44.
char path[] = "m/44'/1729'/0'/0'";

// An optional password, empty by default, to use in deriving a secret master seed from the mnemonic phrase. 
char password[] = "";

#endif
