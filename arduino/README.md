## Tezio Wallet

Welcome to Tezio Wallet, an Arduino-based hardware wallet for the Tezos blockchain. Tezio Wallet is compatible with the Arduino MKR WiFi 1010 and the Arduino Nano 33 IoT, both of which include a cryptographic coprocessor to securely store keys and perform certain crytpographic functions.

###  Installation

Install the Arduino IDE. Download and move the `TezioWallet` folder to your Arduino libraries folder, which is usually `My Documents\Arduino\libraries` on Windows or `Documents\Arduino\libraries` on macOS. Open the Arduino IDE and install the following dependencies using `Tools > Manage Libraries...`.

- ArduinoECCX08
- Crypto
- micro-ecc

### Usage

#### Setup

Running Tezio Wallet on your Arduino device requires that the device first be configured, provisioned, and locked. This is done using the `Tezio_Wallet_Setup.ino` sketch. The sketch runs an interactive setup process using the Arduino IDE's Serial Monitor to share data with the user and get user inputs. The process begins by loading default configuration data onto the Arduino's cryptographic coprocessor. Once the configuration data is written to the device, the user has the option to lock the cofiguration zone. This must be done before the device can be used. Note that the default configuration data stored in the `configuration.h` file is set up to enable current functionality but also to allow for possible future functionality such as encrypted writes to certain slots of the cryptochip's data zone. After the device is configured, the sketch proceeds to derive HD wallet cryptographic keys from a user supplied mnemonic phrase specifice in the `secrets.h` file, or if a mnemonic phrase isn't provided the sketch proceeds to derive a new 24 word phrase using entropy provided by the cryptochip's true random number generator. Mnemonic and key derivation are carried out using specifications outlined in the BIP-0039, BIP-0032, BIP-0044, SLIP-0044, and SLIP-0010. Secret keys are derived for all three elliptic curves supported by the Tezos blockchain: Ed25519, Secp256k1, and NIST P256 (Secp256r1). The keys are written to the Arduino's cryptochip. A user supplied read/write key is also written to the device. The read/write key will allow the user to perform encrypted reads and writes to certain data slots of the device after it is locked. After keys are written, the user is given the option to lock the cryptochip's data zone. After the data zone is locked, clear writes of cryptographic secrets will no longer be supported. The device must be locked before use. 

#### API

After the device is setup, provisioned, and locked, upload the `Tezio_Wallet_API.ino` sketch. The sketch can be run in debug (interactive) mode using the Arduino IDE's serial monitor. However, setting the debug flag to false puts the device into listening mode. It can then be connected via USB to any host machine and recieve and send data via serial. The API sketch invokes the TezioWallet_API class to expose certain cryptographic tools to the host device. Importantly, private (secret) keys never leave the device. In fact, the cryptochip implements hardware support for cryptographic functions using the NIST P256 curve so the NIST P256 secret key never leaves the cryptochip's secure element. This hardware support also means that cryptographic functions involving the NIST P256 curve are much faster than those of the other supported curves. See the .ipynb included in this director for more details about the structure of data packets sent and received using the API and example interactions with a Tezio Wallet using Python. 

## NOTES...
* Notes during development; helpful for me; not very orderly, but will turn into project docs someday...

### Keys Used During Master Secret Derivation

One of the steps in HD wallet creation is master-seed to master-key deviation. This involves HMAC-SHA512 using where the data is the master seed and the key is a character string based on the elliptic curve to be utilized later in the process. I know, and have verified, that for ed25519 the key is "ed25519 seed". According to the SLIP10 documentation posted [here](https://github.com/satoshilabs/slips/blob/master/slip-0010.md), the key for NIST P-256 (aka secp256r1) is "Nist256p1 seed" and the key for secp256k1 (Koblitz curve) is "Bitcoin seed". This last key is defined in BIP32. I'll assume these keys are used by the Tezos Ledger app and aim to verify. 

### Domains of Elliptic Curves

The three elliptic curves used in Tezos have valid private key domains close to 0 to 2<sup>256</sup> - 1 but they each actually have a more limited domains. For initial development I am going to ignore this fact and assume any random integer vetween 0 and 2<sup>256</sup> - 1 is valid key beacause the probability of randomly drawing a number that is not valid is very small. For secp256k1 the domain is integers between 1 and n-1 where
<code> n = 2<sup>256</sup> − 0x14551231950b75fc4402da1732fc9bebf</code>
For secp256r1 the domain is between 1 and n-1 where
<code> n = 2<sup>256</sup> − 2<sup>224</sup> + 2<sup>192</sup> − 0x4319055258e8617b0c46353d039cdaaf</code>
[Source](https://crypto.stackexchange.com/questions/30269/are-all-possible-ec-private-keys-valid)

Interestingly, the SLIP10 reference and [others](https://crypto.stackexchange.com/questions/60866/is-every-bytestring-a-valid-ed25519-private-key) say that any number between 0 (yes zero) and 2^256 - 1 is a valid private key for ed25519 but this makes no sense because the curve itself is a field defined by prime 2^255 - 19, and there is some business about "clamping" some bits to make the key valid. [Source](https://crypto.stackexchange.com/questions/71140/valid-private-keys-on-curve25519). My best guess here is that the implementation of ed25519 takes care of these invalid keys on the fly and any number between 0 and 2^256-1 works. 
 
### About Public Keys

For the ed25519 curve, public keys are 32 bytes. For secp255k1 and P256, public keys are 64 bytes, 32 for an x coordinate and 32 for a y coordinate. My understanding is that the y coordinate can be found from the x coordinate but occurs as y^2 so it can be positive or negative (above or below the x axis) so while the value doesn't need to be preserved whether it is even or odd needs to be preserved (don't understand what even/odd has to do with pos/neg). In compressed form  the public key is the x coordinate with a prefix of 0x02 if the y coordinate is even and 0x03 if it is odd.
