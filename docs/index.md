# (tez-ahy-oh) 

Educational resources and open-source hardware and software tools for the Tezos blockchain.

## [About](pages/about.md)

## Software Tools

### SecretShares

This Python module defines a class, SecretShares, useful for taking a 24-word secret mnemonic phrase and splitting it into an arbitrary number of shares. Each share is itself represented by a 24-word mnemonic phrase. The original secret can be reconstructed from a user-defined minimal threshold of shares. An attacker with fewer than this threshold of shares will be unable to recover the secret or even gain any useful information that would make brute force attacks easier. The secret pnemonic phrase is related to a 32-byte random number (or entropy) as defined by BIP39. The shares are also each represented by a 32-byte sequence or 24-word mnemonic phrase. [More...](pages/secretshares.md)

### BIP32HDKeys

This Python module defines a class, BIP32HDKeys, useful for deriving child keys from a master key, master chaincode, and a derivation path. The class abides by the specifications of BIP32 and SLIP10, the later adapts BIP32 for eliptic curves other than secp256k1. The class specifically approaches child key derivation using the ed25519 curve, which is the default curve used by the Tezos blockchain. [More...](pages/bip32hdkeys.md)

## Tutorials

How art Tezos addresses deterministically determined from private keys? [Click here to find out.](pages/tezos_crypto_intro.md)
