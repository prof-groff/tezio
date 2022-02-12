# Tezio SecretShares

This module defines a class, SecretShares, useful for taking a 24-word secret mnemonic phrase and splitting it into an arbitrary number of shares. Each share is itself represented by a 24-word mnemoni phrase. The original secret can be reconstructed from a user-defined minimal threshold of shares. An attacker with fewer than this threshold of shares will be unable to recover the secret or even gain any useful information that would make brute force attacks easier. 

## Usage
