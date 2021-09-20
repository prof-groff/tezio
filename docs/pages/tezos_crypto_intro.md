# Summary of How Tezos Addresses are Deterministically Related to Private Keys

## Private Keys

Like other blockchains, a Tezos private key is a 32-byte (256-bit) number. Any 32-byte number could be a private key. But, the best way to go about generating a private key is to use a random number generator that is NIST (National Institute of Standards and Technology) certified. This means that the probability of generating a number over the range of all possible values is uniform. In other words, the random number generator generates numbers with a lot or entropy (informationaly speaking).

## Private Key to Public Key

Once a private key is generated, elliptic curve cryptography is used to generate a 64-byte public key from the private key. The public key is compsed of an 32-byte X point and a 32-byte Y point concatenated together, with the X point first. In Tezos the elliptic curve can be Curve25519 (tz1 addresses), Secp256k1 (tz2 addresses, the same curve used in Bitcoin and Ethereum), or P-256 (tz3 addresses, NIST approved and supported by hardward cryptochips, but possibly compromised by the NSA?). 

## Public Key to Tezos Address

The Tezos address is deterministically determined from the public key as follows. First a 33 byte public point is determined. The first byte of the public point is 0x02 if the Y point of the public key is even and 0x03 if the Y is odd. The remaining bytes of the public point are the same as the bytes in the X point of the public key. The public point is then hashed into a 20-byte digest using the Blake2B algorithm. To arrive at the tz3 address prefix<sup>1</sup> the bytes {0x06, 0xa1, 0xa4} are added as a prefix to the hash. The 32-byte SHA-256 hash of this now 23-byte digest is computed. The result is again passed through SHA-256 to yield another 32-byte SHA-256 hash. The first four bytes of this final SHA-256 digrest are appended to the end of the original 23-byte digest yielding 27-bytes. This 27-byte address is converted to base58 yielding the final 36 character tezos address.

## What Prevents The Same Tezos Address From Being Generated Twice?

Nothing, but if people use a random number generator with sufficient entropy to generate private keys, the probability of the same private key being drawn twice is exceedingly rare. Consider that there are 10<sup>256</sup> possible private keys. If all 8 billion people on Earth each had a quadrillion Tezos private keys, this would only exaust 8E-231 percent of the possible private keys. But there is another problem. The private keys generate public keys and these keys are hashed into the tezos addresses. And there are much fewer possilbe addresses. So is it possible that two private keys yield the same address. Yes, but again it is exceedingly unlikely based on how large the space of possibilities is and how the hashing algorithms are designed.

1. For tz1 addresses, the prefix is {0x06, 0xa1, 0x9f}. For tz2 addresses, the prefix is {0x06, 0xa1, 0xa1}.
