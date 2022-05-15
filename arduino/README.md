## Tezio Wallet Notebook
* Notes during development; helpful for me; not very orderly, but will turn into project docs someday...

### Keys Used During Master Secret Derivation

One of the steps in HD wallet creation is master-seed to master-key deviation. This involves HMAC-SHA512 using where the data is the master seed and the key is a character string based on the elliptic curve to be utilized later in the process. I know, and have verified, that for ed25519 the key is "ed25519 seed". According to the SLIP10 documentation posted [here](https://github.com/satoshilabs/slips/blob/master/slip-0010.md), the key for NIST P-256 (aka secp256r1) is "Nist256p1 seed" and the key for secp256k1 (Koblitz curve) is "Bitcoin seed". This last key is defined in BIP32. I'll assume these keys are used by the Tezos Ledger app and aim to verify. 

### Domains of Elliptic Curves

The three elliptic curves used in Tezos have valid private key domains close to 0 to 2<sup>256</sup> but they each actually have a more limited domains. For initial development I am going to ignore this fact and assume any random integer vetween 0 and 2<sup>256</sup> is valid key beacause the probability of randomly drawing a number that is not valid is very small. For secp256k1 the domain is integers between 1 and 
<code> n = 2<sup>256</sup> − 0x14551231950b75fc4402da1732fc9bebf</code>
For secp256r1 the domain is between 1 and 
<code> n = 2<sup>256</sup> − 2<sup>224</sup> + 2<sup>192</sup> − 0x4319055258e8617b0c46353d039cdaaf</code>
[Source](https://crypto.stackexchange.com/questions/30269/are-all-possible-ec-private-keys-valid)
  
 

