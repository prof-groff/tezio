# Tezio Tools

# Contents

- [Tezio BIP32 HD Keys](#bip32hdkeys)
- [Tezio Secret Shares](#secretshares)

<a name="bip32hdkeys">
# Tezio BIP32 HD Keys

The Python module <code>BIP32HDKeys.py</code> defines a class, <code>BIP32HDKeys</code>, useful for deriving child keys from a master key, master chaincode, and a derivation path. The class abides by the specifications of BIP32 and SLIP10, which adapts BIP32 processes for eliptic curves other than secp256k1. The class specifically approaches child key derivation using the ed25519 curve, which is the default curve used by the Tezos blockchain. See the included iPython (Jupyter) Notebook<code>TezioBIP32HDKeys.ipynb</code> for usage exammples. 

## Usage

Download the Tezio repository and copy the <code>tools/python_scripts</code> directory to the project folder or Python module path. Import the BIP32HDKeys class.

```python
from tezio_tools.BIP32HDKeys import BIP32HDKeys
```

Create a BIP32HDKeys object.

```python
myWallet = BIP32HDKeys()
```
    
Calculate a secret seed from a secret 24-word mnemonic phrase, and calculate a master secret key and master chaincode from the seed.

```python
myWallet.phrase_to_seed(phrase)
myWallet.seed_to_master()
```
    
Derive the child secret key and child chaincode along a derivation path specified as a string. Here the path is the default Tezos path using hardened ideces. 

```
myWallet.derivation_path_to_keys("m/44'/1729'/0'/0'")
```
    
Calculate a public key (public point) from the child secret key.

```python
myWallet.sk_to_public_point(myWallet.child_sk)
```
    
Convert the public key to a tezos address by hashing the public key (blake2b) to a 20 byte digest, adding a prefix, appending the first four bytes of the sha256 checksum (double pass), then encoding in base 58 representation. 

```python
print(myWallet.pk_hash(b'\x06\xa1\x9f')) # tz1 prefix
```
    
Add prefixes and encode the child secret key and child public key in base58 representations. 

```python
print(myWallet.sk_base58(b'+\xf6N\x07')) # edsk prefix
print(myWallet.pk_base58(b'\r\x0f%\xd9')) # pk base58 encoded
```
## Dependencies

pyblake2
hashlib
hmac
pysodium

<a name="secretshares">

# Tezio SecretShares

The Python module <code>SecretShares.py</code> defines a class, <code>SecretShares</code>, useful for taking a 24-word secret mnemonic phrase and splitting it into an arbitrary number of shares. Each share is itself represented by a 24-word mnemonic phrase. The original secret can be reconstructed from a user-defined minimal threshold of shares. An attacker with fewer than this threshold of shares will be unable to recover the secret or even gain any useful information that would make brute force attacks easier. The secret pnemonic phrase is related to a 32-byte random number (or entropy) as defined by BIP39. The shares are also each represented by a 32-byte sequence or 24-word mnemonic phrase. 

Each byte of the secret entropy is used to generate a byte of each share using Shamir's Secret Sharing algorithm applied using finite field arithmatic on a field of order 2<sup>8</sup>, GF(2<sup>8</sup>). Shamir's Secret Sharing involves encoding the secret as the y-intercept of a random polynomial of order k-1, where k is the threshold number of shares needed to recover the secret. The bytes of the shares, along with their respective indeces, give (x,y) coordinates on these random polynomials allowing the y-intercept (the secret) to be recovered using langrange polynomial interpolation. See the included iPython (Jupyter) Notebook<code>TezioSecretShare.ipynb</code> for usage exammples. 

## Usage

Download the tezio repository and and copy the <code>tools/python_scripts</code> directory to the project folder or Python module path. Import the SecretShares class.

```python
from tezio_tools.SecretShares import SecretShares
```

Create a SecretShares object.

```python
n = 3 # number of shares of the secret to produce
k = 2 # minimal number of shares needed to recover the secret
vocab = 'bip39english.txt' # path to .txt file containing a bip39 vocabulary
myShares = SecretShares(k, n, vocab)
```
    
## Creating shares from a secret 24-word mnemonic phrase

Convert a 24-word mnemonic phrase into 32-bytes of secret entropy.

```python
phrase = 'motor jazz team food when coach reward hidden obtain faculty tornado crew toast inhale purchase conduct cube omit illness carbon ripple thank crew material'
myShares.phrase_to_secret(phrase)
```
    
Convert secret entropy into share phrases stored as a dictionary. Each key is the index (x-coordinates) used to generate each share.

```python
myShares.secret_to_shares()
print(myShares.secret_share_phrases)

>> {1: 'hurt problem yellow brass youth phrase tomato huge entry mandate icon phrase walnut repair uncover doll bicycle canyon local method hollow mosquito north better',
>> 2: 'insect cabbage bread unfold dog cream hospital genius chalk village aunt cattle silly inner consider must inspire crush spy emotion blade sniff betray liar',
>> 3: 'melt senior depart proud easy rural course gown walnut cargo omit regular talent rally horse wise fiction modify cancel track script live race better'}
```
 
Alternatively, a mnemonic phrase can be converted directly into share phrases.

```python
shares = myShares.phrase_to_shares(phrase)
```
    
## Recovering a secret phrase from share phrases

Load shares and their corresponding indeces. At least the threshold number of shares must be loaded to recover the secret.

```python
myShares.add_share(1, 'hurt problem yellow brass youth phrase tomato huge entry mandate icon phrase walnut repair uncover doll bicycle canyon local method hollow mosquito north better')
myShares.add_share(2, 'insect cabbage bread unfold dog cream hospital genius chalk village aunt cattle silly inner consider must inspire crush spy emotion blade sniff betray liar')
```
    
Recover the secret.

```python
myShares.shares_to_secret()
print(myShares.secret_phrase)
    
 >> 'motor jazz team food when coach reward hidden obtain faculty tornado crew toast inhale purchase conduct cube omit illness carbon ripple thank crew material'
 ```

## Other methods and attributes 

If shares or secrets are already loaded from previous use of <code>.add_share()</code>, <code>.secret_to_shares()</code>, or <code>.phrase_to_shares</code>, they can be cleared.

```python
myShares.clear_secrets()
myShares.clear_shares()
```
    
The raw 32-byte entropy for both the secret phrase and the share phrases can be accessed.

```python
myShares.secret_entropy
myShares.phrase_entropies
```
    
## Dependencies

hashlib
ctypes
secrets
