import hashlib as hl
from ctypes import * # c type uint8_t is used to ensure finite field arithmatic is correct
import secrets

class SecretShares():
    
    def __init__(self, k, n, file):
        # k - threshold, the number of shares required to recover the secret
        # n - the number of shares
        # file - path to file containing the mnemonic vocab
        self.k = k
        self.n = n
        assert self.k <= self.n, 'SECRET RECOVERY REQUIRES MORE SHARES THAN THE THRESHOLD'
        self.file = file
        f = open(self.file, 'r')
        self.vocab = [line.strip('\n') for line in f]
        f.close()
        
        # make lookup table for multiplicitive inverses with BRUTE FORCE!!! (there are only 256 elements in the field)
        self.mult_inverses = []
        for a in range(256):
            for b in range (256):
                if (self.__gf_mult(a,b)==1):
                    self.mult_inverses.append(b)
                    break
        
        self.secret_phrase = None
        self.secret_entropy = None 
        
        self.share_phrases = {}
        self.share_entropies = []
        
        
    def __repr__(self):
        print('Instance of TezioSecretShare\n')
        print('Number of shares:', self.n)
        print('Shares needed for recovery of secret:', self.k)
        print('Vocabulary used:', self.file, '\n')
        print('Secret mnemonic phrase:')
        print(self.secret_phrase, '\n')
        print('Secret entropy:')
        print(self.secret_entropy.hex(), '\n')
        print('Share mnemonic phrases:')
        print(self.share_phrases, '\n')
        print('Share entropy values:')
        print(self.share_entropies, '\n')
        return 'TezioSecretShare'
    
    # recover the index of a word in the vocabulary
    def __word_to_index(self, word): 
        return self.vocab.index(word)
    
    # recover indeces of all words in a mnemonic phrase from the vocabulary
    def __phrase_to_indeces(self, phrase): 
        words = phrase.split(' ')
        indeces = []
        for word in words:
            indeces.append(self.__word_to_index(word))
        return indeces
    
    # convert a base 10 index to an array of 11 binary bits, msb first
    def __index_to_bits(self, index): 
        bits = [0]*11
        for i in range(11):
            if (index//(2**(10-i))):
                bits[i] = 1
                index = index%(2**(10-i))
        return bits
    
    # convert an array of base 10 indeces to an array of binary bits
    def __indeces_to_bits(self, indeces): 
        bits = []
        for index in indeces:
            bits += self.__index_to_bits(index)
        return bits
    
    # convert a mnemonic phrase to an array of binary bits
    def __phrase_to_bits(self, phrase): 
        return self.__indeces_to_bits(self.__phrase_to_indeces(phrase))
    
    # convert an array of bits to a mnemonic phrase
    def __bits_to_phrase(self, bits):
        # iterate through bits with 11 bit chunks
        words = []
        for k in range(0,int(len(bits)/11)):
            chunk = bits[k*11:k*11+11]
            index = 0
            for j in range(11):
                index += chunk[j]*2**(11-1-j)
            words.append(self.vocab[index])
        phrase = ' '.join(words)
        return phrase
    
    # convert an array of binary bits to an array of bytes
    def __bits_to_bytes(self, bits): 
        _bytes = []
        n_bytes = len(bits)//8
        for i in range(n_bytes):
            octet = bits[i*8:i*8+8]
            _byte = 0
            for i in range(8):
                if octet[i] == 1:
                    _byte += (1 << 7-i)
            _bytes += [_byte]
        return _bytes
    
    # convert an array of bytes to an array of bits
    def __bytes_to_bits(self, _bytes):
        bits = []
        for byte in _bytes:
            for i in range(8):
                if (byte & 0b10000000 >> i):
                    bits.append(1)
                else:
                    bits.append(0)
        return bits
    
    # convert a mnemonic phrase to an array of bytes
    def __phrase_to_bytes(self, phrase): 
        return self.__bits_to_bytes(self.__phrase_to_bits(phrase))
    
     # calculate a checksum byte for a bytearray
    def __sha256_checksum(self, _bytes):
        h = hl.sha256()
        h.update(_bytes)
        return h.digest()[0]
    
    # calculate and append a checksum_byte to the end of a byte array
    def __append_checksum_byte(self, _bytes):
        _bytes.append(self.__sha256_checksum(_bytes))
        return _bytes
    
    # s sha256 checksum byte is appended to the end of entropy before parsing into a menmonic phrase
    def __check_discard_csbyte(self, _bytes): 
        cs = _bytes[-1] 
        e = bytes(_bytes[0:-1])
        assert self.__sha256_checksum(e) == cs, 'UNEXPECTED CHECKSUM BYTE'
        return e
    
    # function for performing finite field arithmatics in GF(2^8)
    
    # for GF(2^m) fields, addition and subtraction are equivalent and are bitwise XOR operations
    def __gf_add_sub(self, a: c_ubyte, b: c_ubyte) -> c_ubyte: # c_ubyte is like c++ uint8_t
        return a ^ b
    
    # multipy two numbers in the GF(2^8) using the Russian Pessant Multiplication algorithm 
    # an alternative would be to use carry-less multiplication followed by modular reduction (modulo an irreducible polynomial)
    def __gf_mult(self, a: c_ubyte, b: c_ubyte) -> c_ubyte: # private
        p: c_ubyte = 0 # the result
        while (a and b):
            if (b & 1):
                p = p ^ a
            if (a & 0x80):
                a = (a << 1) ^ 0x11b # irreducible polynomical used for modular reduction is x^8 + x^4 + x^3 + x + 1
            else:
                a = a << 1
            b = b >> 1
        return p
    
    # here division is accomplished by multiplicative inverses found via brute force
    def __gf_div(self, a: c_ubyte, b: c_ubyte) -> c_ubyte: # private
        return self.__gf_mult(a,self.mult_inverses[b-1]) # no entry for zero because division by zero is undefined
    
    # functions for permforming Shamir's Secret Sharing with the secret as the y intercept (x=0) of a polynomial
    
    # evaluate a polynomial in the finite field at a specified location 
    def _eval_poly(self, poly, x):
        # polynomial defined by coefficients in poly
        value = 0
        for coeff in reversed(poly):
            value = self.__gf_mult(value, x)
            value = self.__gf_add_sub(value, coeff)
        return value
    
    # generates random Shamir shares for one byte of the secret
    def __make_random_shares(self, secret_byte):
        assert self.k <= self.n, 'SECRET RECOVERY REQUIRES MORE SHARES THAN THE THRESHOLD'
        poly = [secret_byte] + [secrets.SystemRandom().randint(1,255) for i in range(self.k - 1)] # don't allow any coefficients to be zero
        self.share_entropies= [(i, self._eval_poly(poly, i)) for i in range(1, self.n + 1)]
        return self.share_entropies
    
    # calculate the product of a list of values
    def __product(self, values):
        product = 1
        for term in values:
            product = self.__gf_mult(product, term)
        return product
    
    # find the y-value at x = 0, given n (x, y) points using langrange interpolating polynomials
    def __lagrange_interp(self, xs, ys):
        assert len(set(xs)) == self.k, 'RECOVERY REQUIRES THAT ALL SHARE POINTS BE DISTINCT'
        numerators = []  # avoid inexact division
        denominators = []
        for i in range(self.k):
            not_xs_i = list(xs)
            xs_i = not_xs_i.pop(i)
            numerators.append(self.__product(not_xs_i))
            denominators.append(self.__product(self.__gf_add_sub(xs_i,o) for o in not_xs_i))
        cden = self.__product(denominators) # cumulative denominator
    
        cnum = 0 # cumulative numerator
        for i in range(self.k):
            cnum = self.__gf_add_sub(cnum, self.__gf_div(self.__gf_mult(self.__gf_mult(numerators[i], cden), ys[i]), denominators[i]))
   
        return self.__gf_div(cnum, cden)
    
    # recover the secret from share points (x, y points on the polynomial).
    def __recover_secret(self, shares_onebyte):
        assert len(shares_onebyte) >= self.k, 'INSUFFICIENT SHARES TO RECOVER SECRET'
        xs, ys = zip(*shares_onebyte)
        return self.__lagrange_interp(xs, ys)
    
    # convert 32 bytes of entropy into a 24 word mnemonic phrase
    def __entropy_to_phrase(self, entropy):
        _bytes = self.__append_checksum_byte(bytearray(entropy)) # add checksum byte
        bits = self.__bytes_to_bits(_bytes)
        phrase = self.__bits_to_phrase(bits)
        return phrase
    
    # convert a 24 word mnemonic phrase to the underlying 32 bytes of entropy
    def __phrase_to_entropy(self, phrase):
        return self.__check_discard_csbyte(self.__phrase_to_bytes(phrase))
    
    def __entropy_to_shares(self):
        assert len(self.share_entropies) == 0, 'A SECRET IS ALREADY STORED; USE .clear_secrets() TO PROCEED'
        for i in range(len(self.secret_entropy)):
            self.share_entropies += [self.__make_random_shares(self.secret_entropy[i])]
            
        share_entropies_unpacked = []
        for i in range(self.n):
            share_entropies_unpacked += [[row[i][1] for row in self.share_entropies]]  
            
        for i in range(self.n):
            _bytes = self.__append_checksum_byte(bytearray(share_entropies_unpacked[i]))
            self.share_phrases[i+1] = self.__bits_to_phrase(self.__bytes_to_bits(_bytes))
            
        return self.share_phrases
    

    # PUBLIC
    
    def phrase_to_secret(self, phrase):
        self.secret_phrase = phrase
        self.secret_entropy = self.__phrase_to_entropy(phrase)
        return self.secret_entropy.hex()
    
    def phrase_to_shares(self, phrase):
        self.phrase_to_secret(phrase)
        return self.__entropy_to_shares()
    
    def secret_to_shares(self):
        assert self.secret_entropy != None, 'NO SECRET STORED, USE .phrase_to_secret() FIRST or .phrase_to_shares()'
        return self.__entropy_to_shares()
    
    def add_share(self, index, share):
        self.share_phrases[index] = share
        return self.share_phrases
    
    def clear_shares(self):
        _input = input('THIS WILL DELETE ALL STORED SHARES. DO YOU WISH TO CONTINUE (Y OR N)? ')
        if _input == 'Y':
            self.share_phrases = {}
            self.share_entropies = []
            return True
        else:
            return False
    
    def clear_secrets(self):
        _input = input('THIS WILL DELETE ALL STORED SECRETS. DO YOU WISH TO CONTINUE (Y OR N)? ')
        if _input == 'Y':
            self.secret_phrase = None
            self.secret_entropy = None
            return True
        else:
            return False
    
    def shares_to_secret(self):
        assert len(self.share_phrases) >= self.k, 'INSUFFICIENT SHARES TO RECOVER SECRET'
        assert self.secret_entropy is None, 'A SECRET IS ALREADY STORED; USE .clear_secrets() TO PROCEED'
        assert self.secret_phrase is None, 'A SECRET IS ALREADY STORED; USE .clear_secrets() TO PROCEED'
        
        # shares_phrase to share_entropies
        share_entropies_unpacked = []
        shares_xs = []
        for xs, share in self.share_phrases.items():
            share_phrase = share
            share_entropies_unpacked += [list(self.__check_discard_csbyte(self.__phrase_to_bytes(share_phrase)))]
            shares_xs += [xs]
        
        self.share_entropies = [] # ensure share_entropies is empty
        nbytes = len(share_entropies_unpacked[0])
        nshares = len(share_entropies_unpacked)
        for i in range(nbytes):
            self.share_entropies += [[(shares_xs[j], share_entropies_unpacked[j][i]) for j in range(nshares)]]
        
        
        temp_secret = []
        for shares_onebyte in self.share_entropies:
            temp_secret.append(self.__recover_secret(shares_onebyte))
            
        self.secret_entropy = temp_secret
        self.secret_phrase = self.__entropy_to_phrase(self.secret_entropy)
        
        return self.secret_phrase