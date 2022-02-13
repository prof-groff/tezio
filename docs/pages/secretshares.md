# Tezio SecretShares

This Python module defines a class, SecretShares, useful for taking a 24-word secret mnemonic phrase and splitting it into an arbitrary number of shares. Each share is itself represented by a 24-word mnemonic phrase. The original secret can be reconstructed from a user-defined minimal threshold of shares. An attacker with fewer than this threshold of shares will be unable to recover the secret or even gain any useful information that would make brute force attacks easier. The secret pnemonic phrase is related to a 32-byte random number (or entropy) as defined by BIP39. The shares are also each represented by a 32-byte sequence or 24-word mnemonic phrase. 

Each byte of the secret entropy is used to generate a byte of each share using Shamir's Secret Sharing algorithm applied using finite field arithmatic on a field of order 2<sup>8</sup>, GF(2<sup>8</sup>). Shamir's Secret Sharing involves encoding the secret as the y-intercept of a random polynomial of order k-1, where k is the threshold number of shares needed to recover the secret. The bytes of the shares, along with their respective indeces, give (x,y) coordinates on these random polynomials allowing the y-intercept (the secret) to be recovered using langrange polynomial interpolation. 

## Usage

Download and copy the <code>tezio</code> directory to the project folder or Python module path. Import the SecretShares class.

[Link to Github repository.](https://github.com/prof-groff/tezio)

    from tezio.SecretShares import SecretShares

Create a SecretShares object.

    n = 3 # number of shares of the secret to produce
    k = 2 # minimal number of shares needed to recover the secret
    vocab = 'bip39english.txt' # path to .txt file containing a bip39 vocabulary
    myShares = SecretShares(k, n, vocab)
    
### Creating shares from a secret 24-word mnemonic phrase

Convert a 24-word mnemonic phrase into 32-bytes of secret entropy.

    phrase = 'motor jazz team food when coach reward hidden obtain faculty tornado crew toast inhale purchase conduct cube omit illness carbon ripple thank crew material'
    myShares.phrase_to_secret(phrase)
    
Convert secret entropy into share phrases stored as a dictionary. The keys are the index (x-coordinate) used to generate each share.

    myShares.secret_to_shares()
    print(myShares.secret_share_phrases)
    
    >> {1: 'hurt problem yellow brass youth phrase tomato huge entry mandate icon phrase walnut repair uncover doll bicycle canyon local method hollow mosquito north better',
    >> 2: 'insect cabbage bread unfold dog cream hospital genius chalk village aunt cattle silly inner consider must inspire crush spy emotion blade sniff betray liar',
    >> 3: 'melt senior depart proud easy rural course gown walnut cargo omit regular talent rally horse wise fiction modify cancel track script live race better'}
 
Alternatively, a mnemonic phrase can be converted directly into share phrases.

    shares = myShares.phrase_to_shares(phrase)
    
### Recovering a secret phrase from share phrases

Load shares and their corresponding indeces. At least the threshold number of shares must be loaded to recover the secret.

    myShares.add_share(1, 'hurt problem yellow brass youth phrase tomato huge entry mandate icon phrase walnut repair uncover doll bicycle canyon local method hollow mosquito north better')
    myShares.add_share(2, 'insect cabbage bread unfold dog cream hospital genius chalk village aunt cattle silly inner consider must inspire crush spy emotion blade sniff betray liar'
    
Recover the secret.

    myShares.shares_to_secret()
    print(myShares.secret_phrase)
    
    >> 'motor jazz team food when coach reward hidden obtain faculty tornado crew toast inhale purchase conduct cube omit illness carbon ripple thank crew material'

### Other methods and attributes 

If shares or secrets are already loaded from previous use of <code>.add_share()</code>, </code>.secret_to_shares()</code>, or <code>.phrase_to_shares</code>, they can be cleared.

    myShares.clear_secrets()
    myShares.clear_shares()
    
The raw 32-byte entropy for both the secret phrase and the share phrases can be accessed.

    myShares.secret_entropy
    myShares.phrase_entropies
    
### Dependencies

    hashlib
    ctypes
    secrets
