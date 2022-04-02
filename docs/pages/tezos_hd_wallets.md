## How Tezos Keys are Derived

If you use Tezos, chances are you use Temple, Kukai, or a Ledger hardware wallet. When you create an HD wallet (HD means hierarchical deterministic), you are given a 24-word secret mnemonic phrase from which your keys and Tezos address are somehow derived. Get ready because I'm going to explain the journey from phrase to Tezos address. I'm specifically going to focus on <code>tz1</code> addresses that rely on the Ed25519 elliptic curve. Addresses that begin with <code>tz2</code> or <code>tz3</code> use alternative elliptic curves and thus have slightly different derivations. 

## It Begins with Secret Entropy

Like other blockchains, Tezos keys begin as a secret 32-byte (256-bit) number. Any 32-byte number could be a used, but it should be a random number. The best way to go about generating this random number is to use a random number generator that is NIST (National Institute of Standards and Technology) certified. This means that the probability of generating a number over the range of all possible values is uniform. In other words, the random number generator generates numbers with a lot or entropy (informationally speaking). Therefore, this secret 32-byte number is often called entropy. It is secret. Anybody who gets your entropy can get your keys.

## Entropy Leads to a Secret Mnemonic Phrase

The first step to derive a secret 24-word mnemonic phrase from the entropy is to add one additional byte to the end of the entropy. This 33rd byte is the first byte you get when you pass the entropy through the SHA-256 hashing algorithm. Next, this 33-byte (264-bit) number is divided up into twenty-four 11-bit chunks. Each chunk is interpreted as the index of a word in a 2<sup>11</sup> or 2048-word vocabulary defined by BIP-39 (Bitcoin improvement proposal 39) yielding the 24-word mnemonic phrase.  Like entropy, the mnemonic phrase is secret. Keep it safe.

## Mnemonic Phrase to Secret Master Seed

The 24-words in the mnemonic phrase are concatenated together with one space between each word and interpreted as a character string. This string is passed through the PBKDF2 (password-based key derivation function 2) algorithm, which repeatedly passes the data, 2048 times, through the HMAC (hash-based message authentication code) algorithm, which itself uses the SHA-512 hashing algorithm. Thus, this algorithm is sometimes referred to as PBKDF2-HMAC-SHA512. The algorithm takes an optional password (don't forget it) and begins the repeated application of HMAC using the salt <code>mnemonic</code>. This password is the one you use when recovering your wallet from your secret mnemonic phrase in Temple or Kukai. The result of this process is a 64-byte secret master seed. Don't share it.

## Master Seed to Master Secret Key and Master Chain Code

The master seed is again passed through the HMAC algorithm using the SHA-512 hashing function and the key <code>ed25519 seed</code>. This yields a new 64-byte number. The first 32-bytes is your master secret key; the second 32-bytes is your master chain code. Both are secret, don't share them.

## Master Secret Key and Master Chain Code to Secret Key

This step is difficult to explain compactly. For now, let me say that it involves repeated application of the HMAC-SHA512 algorithm beginning with the master secret key and master chain code and resulting at each step in a child secret key and child chain code. At each step the HMAC uses the previous step's chain code as the key and the previous step's secret key with some extra bits appended as the data. These extra bits (four bytes worth actually) are provided by a derivation path. For Tezos, the default derivation path is <code>m/44'/1729'/0'/0'</code>. When the process gets to the end of the derivation path the resulting child secret key is your final secret key. Don't share it. This process is described in BIP-32 with modification for the Ed25519 elliptic curve described in SLIP-10. 

## Secret Key to Public Key and Public Key Hash (Tezos Address)

The secret key from the previous step is used to derive a corresponding public key using the Ed25519 elliptic curve. The public key will be shared with the world and used for signature verification on the Tezos network. The public key is also used to derive a Tezos address. First it is hashed using the Blake2b hashing algorithm with a digest size of 20 bytes. A three-byte prefix is added, <code>0x06, 0xa1, 0xa4</code>, and then this 23-byte sequence is passed through the SHA-256 hashing algorithm. The result of this hash (32-bytes) is passed through SHA-256 again. The first 4-bytes of this second hash is appended to the original 23-byte sequence. Finally, the 27-bytes is encoded in base58 yielding a 36-character address beginning with <code>tz1</code>. The End!
