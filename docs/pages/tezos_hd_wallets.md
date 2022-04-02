## How Tezos Keys are Derived

If you use Tezos, chances are you use Temple, Kukai, or a Ledger hardware wallet. When you create an HD wallet (HD means hierarchical deterministic), you are given a 24-word secret mnemonic phrase from which your keys and Tezos address are somehow derived. Get ready becauce I'm going to explain the journey from phrase to tezos address. I'm specifically going to focus on <code>tz1</code> addresses that rely on the Ed25519 elliptic curve. Addresses that begin with <code>tz2</code> or <code>tz3</code> use alternative elliptic curves and thus have slightly different derivations. 

## It Begins with Secret Entropy

Like other blockchains, Tezos keys begin as a secret 32-byte (256-bit) number. Any 32-byte number could be a used, but it should be a random number. The best way to go about generating this random number is to use a random number generator that is NIST (National Institute of Standards and Technology) certified. This means that the probability of generating a number over the range of all possible values is uniform. In other words, the random number generator generates numbers with a lot or entropy (informationaly speaking). Therfore, this secret 32-byte number is often called entropy. It is secret. Anybody who gets your entropy can get your keys.

## Entropy Leads to a Secret Mnemonic Phrase
