## (tez-ee-oh or tez-ahy-oh, you decide) 

Hardware and software tools for the Tezos blockchain developed by a guy in West Virginia, USA. 

### SecretShares

This Python module defines a class, SecretShares, useful for taking a 24-word secret mnemonic phrase and splitting it into an arbitrary number of shares. Each share is itself represented by a 24-word mnemonic phrase. The original secret can be reconstructed from a user-defined minimal threshold of shares. An attacker with fewer than this threshold of shares will be unable to recover the secret or even gain any useful information that would make brute force attacks easier. The secret pnemonic phrase is related to a 32-byte random number (or entropy) as defined by BIP39. The shares are also each represented by a 32-byte sequence or 24-word mnemonic phrase. [More...](pages/secretshares.md)
