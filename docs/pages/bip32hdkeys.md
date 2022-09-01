# Tezio BIP32HDKeys

This Python module defines a class, BIP32HDKeys, useful for deriving child keys from a master key, master chaincode, and a derivation path. The class abides by the specifications of BIP32 and SLIP10, which adapts BIP32 processes for eliptic curves other than secp256k1. The class specifically approaches child key derivation using the ed25519 curve, which is the default curve used by the Tezos blockchain. 

## Usage

Download the tezio repository and copy the <code>tezio_tools</code> directory to the project folder or Python module path. Import the BIP32HDKeys class.

[Link to Github repository.](https://github.com/prof-groff/tezio)

    from tezio_tools.BIP32HDKeys import BIP32HDKeys

Create a BIP32HDKeys object.

    myWallet = BIP32HDKeys()
    
Calculate a secret seed from a secret 24-word mnemonic phrase, and calculate a master secret key and master chaincode from the seed.

    myWallet.phrase_to_seed(phrase)
    myWallet.seed_to_master()
    
Derive the child secret key and child chaincode along a derivation path specified as a string. Here the path is the default Tezos path using hardened ideces. 

    myWallet.derivation_path_to_keys("m/44'/1729'/0'/0'")
    
Calculate a public key (public point) from the child secret key.

    myWallet.sk_to_public_point(myWallet.child_sk)
    
Convert the public key to a tezos address by hashing the public key (blake2b) to a 20 byte digest, adding a prefix, appending the first four bytes of the sha256 checksum (double pass), then encoding in base 58 representation. 

    print(myWallet.pk_hash(b'\x06\xa1\x9f')) # tz1 prefix
    
Add prefixes and encode the child secret key and child public key in base58 representations. 
    print(myWallet.sk_base58(b'+\xf6N\x07')) # edsk prefix
    print(myWallet.pk_base58(b'\r\x0f%\xd9')) # pk base58 encoded

    
### Dependencies

    pyblake2
    hashlib
    hmac
    pysodium
