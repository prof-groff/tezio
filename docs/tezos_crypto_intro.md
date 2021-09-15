## Private Keys to Tezos Address

Like other blockchains, the native form a a Tezos private key is a 32-byte (256-bit) number. Any 32-byte number could be a private key. But, the best way to go about generating a private key is to use a random number generator that is NIST (National Institute of Standards and Technology) certified. This means that the probability of generating a number over the range of all possible values is uniform. In other words, the random number generator generates numbers with a lot or entropy (informationly speaking). Once a private key is generated, elliptic curve cryptography is used to generate a 64-byte public key. In Tezos the elliptic curve can be Curve25519 (tz1 addresses), Secp256k1 (tz2 addresses, the same curve used in Bitcoin and Ethereum), or P-256 (tz3 addresses, NIST approved but possibly compromised by the NSA). The Tezos address is deterministically determined from the private key as follows:


