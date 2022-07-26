from pyblake2 import blake2b
import hashlib as hl
import hmac
from tezio.Utils import Utils
import pysodium

class BIP32HDKeys():
    
    def __init__(self):
        # do something
        self.secret_phrase = None
        self.secret_seed = None
        self.derivation_path = None
        self.master_sk = None
        self.master_cc = None
        self.child_sk = None
        self.child_cc = None
        self.public_point = None
        self.secret_exponent = None
        self.tzaddress = None
        self.sk_b58 = None
        
        return
    
    def __hmac_sha512(self, key, data):
        I = (hmac.new(key, data, hl.sha512)).digest()
        IL = I[:32]
        IR = I[32:]
        return IL, IR
    
    def __parse_path(self, path: str): # default tezos path
        if path.endswith('/'):
            path = path[:-1]
        path = path.split('/')
        
        if path[0] == 'm' or path[0] == '':
            path = path[1:]
        
        indeces = []
        for each in path:
            if each.endswith("'"): # hardened
                index = (1 << 31) + int(each[:-1])
                index = index.to_bytes(4,'big') # from int to bytes
            else:
                index = int(each)
            indeces.append(index)
    
        return indeces
    
    def __parent_to_child(self, parent_sk, parent_cc, index):
        data = b'\x00' + parent_sk + index
        child_sk, child_cc = self.__hmac_sha512(parent_cc, data)
        return child_sk, child_cc
    
    
    # do double sha256 checksum and return the last four bytes of the digest
    def __sha256_checksum(self, _bytes):
        digest = hl.sha256(hl.sha256(_bytes).digest()).digest()
        return digest[:4]
    
    # 24 word mnemonic phrase to secret seed
    def phrase_to_seed(self, phrase:str, password:str = ''):
        self.secret_phrase = phrase 
        passphrase = 'mnemonic' + password
        self.secret_seed = hl.pbkdf2_hmac('sha512', self.secret_phrase.encode('utf-8'), passphrase.encode('utf-8'), 2048)
        return self.secret_seed.hex()
    
    # calcuolate master secret key and master chaincode from secret seed
    def seed_to_master(self):
        self.master_sk, self.master_cc = self.__hmac_sha512(b'ed25519 seed', self.secret_seed)
        return self.master_sk.hex(), self.master_cc.hex()
    
    def derivation_path_to_keys(self, path:str = "m/44'/1729'/0'/0'"):
        self.derivation_path = path
        indeces = self.__parse_path(self.derivation_path)
        self.child_sk = self.master_sk
        self.child_cc = self.master_cc
        for index in indeces:
            self.child_sk, self.child_cc = self.__parent_to_child(self.child_sk, self.child_cc, index)
    
        return self.child_sk.hex(), self.child_cc.hex()
    
    def base58_checksum(self, data: bytes, prefix: bytes):
        _bytes = prefix + data
        checksum = self.__sha256_checksum(_bytes)
        b58 = Utils.base58(_bytes + checksum)
        return b58
    
    def sk_to_public_point(self, sk): # for Ed25519, the public point is the public key and the secret exponent is the sk || pk
        self.public_point, self.secret_exponent = pysodium.crypto_sign_seed_keypair(seed=sk)
        return self.public_point, self.secret_exponent
        
    def pk_hash(self, prefix: bytes = b'\x06\xa1\x9f'): # default prefix is tz1
        pkh = blake2b(data=self.public_point, digest_size=20).digest()
        self.tzaddress = self.base58_checksum(pkh, prefix)
        return self.tzaddress
    
    def sk_base58(self, prefix: bytes = b'+\xf6N\x07'):
        self.sk_b58 = self.base58_checksum(self.secret_exponent, prefix)
        return self.sk_b58
    
    def pk_base58(self, prefix: bytes = b'\r\x0f%\xd9'):
        self.pk_b58 = self.base58_checksum(self.public_point, prefix)
        return self.pk_b58