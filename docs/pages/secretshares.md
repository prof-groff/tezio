# Tezio SecretShares

This module defines a class, SecretShares, useful for taking a 24-word secret mnemonic phrase and splitting it into an arbitrary number of shares. Each share is itself represented by a 24-word mnemoni phrase. The original secret can be reconstructed from a user-defined minimal threshold of shares. An attacker with fewer than this threshold of shares will be unable to recover the secret or even gain any useful information that would make brute force attacks easier. 

## Usage

Download and copy the <code>tezio</code> directory to the project folder or Python module path. Import the SecretShares class.

    from tezio.SecretShares import SecretShares

Create a SecretShares object.

    n = 3 # number of shares of the secret to produce
    k = 2 # minimal number of shares needed to recover the secret
    vocab = 'bip39english.txt' # path to .txt file containing a bip39 vocabulary
    myShares = SecretShares(k, n, vocab)

Convert a 24-word mnemonic phrase into 32-bytes of secret entropy.

    phrase = 'motor jazz team food when coach reward hidden obtain faculty tornado crew toast inhale purchase conduct cube omit illness carbon ripple thank crew material'
    myShares.phrase_to_secret(phrase)
    
Convert secret entropy into share phrases stored as a dictionary. The keys are the index (x-coordinate) used to generate each share.

    shares = myShares.secret_to_shares()
    print(shares)
    
    >> {1: 'hurt problem yellow brass youth phrase tomato huge entry mandate icon phrase walnut repair uncover doll bicycle canyon local method hollow mosquito north better',
    >> 2: 'insect cabbage bread unfold dog cream hospital genius chalk village aunt cattle silly inner consider must inspire crush spy emotion blade sniff betray liar',
    >> 3: 'melt senior depart proud easy rural course gown walnut cargo omit regular talent rally horse wise fiction modify cancel track script live race better'}
  
