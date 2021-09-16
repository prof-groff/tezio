## Private Keys

Like other blockchains, a Tezos private key is a 32-byte (256-bit) number. Any 32-byte number could be a private key. But, the best way to go about generating a private key is to use a random number generator that is NIST (National Institute of Standards and Technology) certified. This means that the probability of generating a number over the range of all possible values is uniform. In other words, the random number generator generates numbers with a lot or entropy (informationly speaking). 

## Private Key to Public Key

Once a private key is generated, elliptic curve cryptography is used to generate a 64-byte public key from the private key. The public key is compsed of an 32-byte X point and a 32-byte Y point concatenated together, with the X point first. In Tezos the elliptic curve can be Curve25519 (tz1 addresses), Secp256k1 (tz2 addresses, the same curve used in Bitcoin and Ethereum), or P-256 (tz3 addresses, NIST approved and supported by hardward cryptochips, but possibly compromised by the NSA?). 

## Public Key to Tezos Address

The Tezos address is deterministically determined from the public key as follows. First a 33 byte public point is determined. The first byte of the public point is 0x02 if the Y point of the public key is even and 0x03 if the Y is odd. The remaining bytes of the public point are the same as the bytes in the X point of the public key. The public point is then hashed into a 20-byte digest using the Blake2B algorithm. To arrive at the tz3 address prefix the bytes {0x06, 0xa1, 0xa4} are added as a prefix to the hash. The 32-byte SHA-256 hash of this now 23-byte digest is computed. The result is again passed through SHA-256 to yield another 32-byte SHA-256 hash. The first four bytes of this final SHA-256 digrest is appended to the end of the original 23-byte digest. 


