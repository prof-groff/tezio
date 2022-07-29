## Tezio Wallet

Welcome to Tezio Wallet, an Arduino-based hardware wallet for the Tezos blockchain. Tezio Wallet is compatible with the Arduino MKR WiFi 1010 and the Arduino Nano 33 IoT, both of which include a cryptographic coprocessor to securely store keys and perform certain crytpographic functions. 

See the (Tezio Wallet Project Page)[https://tezio.cc/pages/tezio_wallet.html) for installation notes and an API reference. 

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
