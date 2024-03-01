/* MIT License

Copyright (c) 2024 Jeffrey R. Groff

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

#include "crypto_helpers.h"

uint8_t hex_char_to_num(char c) {
  uint8_t h;
  if (c >= 'A' && c <= 'F') { // uppercase
    h = c - 55;
  }
  else if (c >= 'a' && c <= 'f') { // lowercase
    h = c - 87;
  }
  else if (c >= 48 && c <= 57) { // number
    h = c - 48;
  }
  else {
    h = NULL;
  }
  return h; 
}

char num_to_hex_char(uint8_t n) {
   char c;
   if (n >= 0 && n <= 9) {
       c = '0' + n;
   }
   else if (n >= 10 && n <= 15) {
       c = 'A' - 10 + n;
   }
   else {
       c = NULL;
   }
   return c;
}

uint16_t hex_chars_to_byte_array(char *s, uint16_t s_length, uint8_t *ba, uint16_t ba_length) {
    uint16_t i, j;
    
    // only works if s_length is odd (null terminator is included)
    if (s_length % 2 == 0) {
        return 0;
    }
  
    for (i = 0, j = 1; j < s_length - 1; i += 2, j += 2) {
        ba[i/2] = hex_char_to_num(s[j]) + (hex_char_to_num(s[i]) << 4);
    }
    return 1;
}

uint16_t byte_array_to_hex_chars(uint8_t *ba, uint16_t ba_length, char *s, uint16_t s_length) {
	uint16_t i;
	
	if (s_length % 2 == 0) {
		return 0;
	}
	
	for (i = 0; i < ba_length; i ++) {
		s[2*i] = num_to_hex_char(ba[i] >> 4); // like int division by 16
		s[2*i+1] = num_to_hex_char(ba[i] % 16); 
	}
	
	s[2*ba_length] = '\0';
	
	return 1;
}

void chars_to_bytes(const char *c, uint16_t n_chars, uint8_t *b) {
  // n_chars is the number of characters not including any null character terminiating the string
  for (int i = 0; i < n_chars; i++) {
    b[i] = c[i]; // 
  }
}


void derive_public_key(uint8_t *sk, uint8_t curve, uint8_t *pk) {
    switch (curve) {
        case SECP256K1:
            {
                const struct uECC_Curve_t * c = uECC_secp256k1();
                uECC_compute_public_key(sk, pk, c);
                return;
            }
        case NISTP256:
        case NISTP256_AUTH:
            {
                const struct uECC_Curve_t * c = uECC_secp256r1();
                uECC_compute_public_key(sk, pk, c);
                return;
            }
        case ED25519:
            {
                Ed25519::derivePublicKey(pk,  sk);
                return;
            }
        default:
            {
                const struct uECC_Curve_t * c = uECC_secp256r1();
                uECC_compute_public_key(sk, pk, c);
                return;
            }
    }
 
}

void compress_public_key(uint8_t *pk, uint8_t curve, uint8_t *cpk) {
	
	if (curve == ED25519) {
		memcpy(cpk, pk, 32); // pk is only 32 bytes, no compression needed
	}
	else {
		if (pk[63]%2 == 0) { // even
			cpk[0] = 0x02;
		}
		else {
			cpk[0] = 0x03;
		}
		memcpy(&cpk[1], pk, 32); // final compressed pk is 33 bytes
	}
	return;
	
}

void generate_public_key_hash(uint8_t *pk, uint8_t curve, char *pk_hash) {
	
	uint16_t pk_length;
	uint8_t prefix[3];
	
	switch (curve) {
		case ED25519: 
			{
				memcpy(prefix, TZ1_PREFIX, 3); // tz1
				pk_length = 32;
				break;
			}
		case SECP256K1: 
			{
				memcpy(prefix, TZ2_PREFIX, 3); // tz2
				pk_length = 33;
				break;
			}
		case NISTP256:
		case NISTP256_AUTH:
			{
				memcpy(prefix, TZ3_PREFIX, 3); // tz3
				pk_length = 33;
				break;
			}
	}

    BLAKE2b blake2b; 
    uint8_t pkhash[20];
    blake2b.reset(20);
    blake2b.update(pk, pk_length);
    blake2b.finalize(pkhash, 20);
    uint8_t tzpkhash[3 + sizeof(pkhash)];
    memcpy(&tzpkhash[0], &prefix[0], 3);
    memcpy(&tzpkhash[3], &pkhash[0], sizeof(pkhash));
    uint8_t sha256a[32];
    uint8_t sha256b[32]; // apply sha256 twice
    sha256_func_host(tzpkhash, 23, sha256a);
    delay(100);
    sha256_func_host(sha256a, 32, sha256b);
    uint8_t tzaddress[27];
    memcpy(&tzaddress[0], &tzpkhash[0], 23);
    memcpy(&tzaddress[23], &sha256b[0], 4);
	char _buffer[60];
    memset(_buffer, '\0', 60);
    size_t outlength = base58_encode(tzaddress, sizeof(tzaddress), _buffer);
	memcpy(pk_hash, _buffer, outlength); 
	
	return;

}

uint16_t public_key_base58(uint8_t *pk, uint8_t curve, char *pkb58) {
	
	uint16_t pkLength;
	uint8_t prefix[4];
	
	switch (curve) {
		case ED25519: 
			{
				memcpy(prefix, TZ1_PK, 4); // tz1
				pkLength = 32;
				break;
			}
		case SECP256K1: 
			{
				memcpy(prefix, TZ2_PK, 4); // tz2
				pkLength = 33;
				break;
			}
		case NISTP256:
		case NISTP256_AUTH:
			{
				memcpy(prefix, TZ3_PK, 4); // tz3
				pkLength = 33;
				break;
			}
	}

    uint8_t pkBase58[4 + pkLength + 4]; // prefix + key + checksum
    memcpy(&pkBase58[0], &prefix[0], 4);
    memcpy(&pkBase58[4], &pk[0], pkLength);
    uint8_t sha256a[32];
    uint8_t sha256b[32]; // apply sha256 twice
    sha256_func_host(&pkBase58[0], 4 + pkLength, sha256a);
    sha256_func_host(sha256a, 32, sha256b);
    memcpy(&pkBase58[4 + pkLength], &sha256b[0], 4); 
	char _buffer[96]; // will be either 54 or 55 characters
    memset(_buffer, '\0', sizeof(_buffer));
    uint16_t outLength = base58_encode(pkBase58, sizeof(pkBase58), _buffer);
	memcpy(pkb58, _buffer, outLength); 
	
	return outLength;

}

void generate_entropy(uint8_t *entropy, uint16_t entropy_length) {
    randomSeed(analogRead(0)); // try to get some randomness from the system
    for (uint16_t i = 0; i < entropy_length; i ++) {
        entropy[i] = random(0, 256); 
    }
    
	return;
}

uint16_t secret_key_base58(uint8_t *sk, uint8_t curve, char *skb58) {
	
	uint16_t skLength;
	uint16_t pkLength;
	uint8_t prefix[4];
	uint8_t pk[32];
	
	switch (curve) {
		case ED25519: 
			{
				memcpy(prefix, TZ1_SKPK, 4); // tz1
				skLength = 32; 
				pkLength = 32; // customary to append public key to secret key before encoding
				break;
			}
		case SECP256K1: 
			{
				memcpy(prefix, TZ2_SK, 4); // tz2
				skLength = 32;
				break;
			}
		case NISTP256:
		case NISTP256_AUTH:
			{
				memcpy(prefix, TZ3_SK, 4); // tz3
				skLength = 32;
				break;
			}
	}

    uint8_t skBase58[4 + skLength + pkLength + 4]; // prefix + secret key + public key + checksum , enough space for ed25519 keys
    memcpy(&skBase58[0], &prefix[0], 4);
    memcpy(&skBase58[4], &sk[0], skLength);
    
    uint8_t sha256a[32];
    uint8_t sha256b[32]; // apply sha256 twice
    uint16_t outLength;
    
    char _buffer[99]; // will be either 54 or 98 characters plus null terminator
    
    if (curve == ED25519) {
    	derive_public_key(sk, ED25519, pk);
    	memcpy(&skBase58[4+skLength], &pk[0], 32);
    	sha256_func_host(&skBase58[0], 4 + skLength + pkLength, sha256a);
    	sha256_func_host(sha256a, 32, sha256b);
    	memcpy(&skBase58[4 + skLength + pkLength], &sha256b[0], 4); 
    	memset(_buffer, '\0', sizeof(_buffer));
    	outLength = base58_encode(skBase58, 4 + skLength + pkLength + 4, _buffer);
		memcpy(skb58, _buffer, outLength); 
    }
    else {
    	sha256_func_host(&skBase58[0], 4 + skLength, sha256a);
    	sha256_func_host(sha256a, 32, sha256b);
    	memcpy(&skBase58[4 + skLength], &sha256b[0], 4); 
    	memset(_buffer, '\0', sizeof(_buffer));
    	outLength = base58_encode(skBase58, 4 + skLength + 4, _buffer);
		memcpy(skb58, _buffer, outLength); 
	}
	
	return outLength;

}

uint16_t encode_public_key(uint8_t *buffer, uint16_t rawKeyLength, uint8_t pkForm, uint8_t curve) {
	uint16_t replyLength;
	if (pkForm == 1) {
		replyLength = rawKeyLength; // raw key wanted
	}
	else {
		// compress key
		uint8_t compressedKey[33]; // might be 32 or 33 bytes
		compress_public_key(buffer, curve, compressedKey);
		if (pkForm == 2) {
			if (curve == ED25519) {
				memcpy(buffer, compressedKey, 32);
				replyLength = 32;
			}
			else {
				memcpy(buffer, compressedKey, 33);
				replyLength = 33; 
			}
		}
		else if (pkForm == 3) {
			// base58 encode
			char pkb58[56];
			replyLength = public_key_base58(compressedKey, curve, pkb58);
			replyLength-=1; // char *pkb58 include null terminator
			memcpy(buffer, pkb58, replyLength); // reply could be either 54 or 55 bytes
		}
		else if (pkForm = 4) {
			char pkhash[37];
			generate_public_key_hash(compressedKey, curve, pkhash);
			memcpy(buffer, pkhash, 36); // always 36 characters in tz address
			replyLength = 36;
		}
	}
	
	return replyLength;
}

uint16_t secp256k1_sign(uint8_t *hash, uint8_t *sk, uint8_t *signature) {
  	uECC_set_rng(&RNG);
	const struct uECC_Curve_t * curve = uECC_secp256k1();
    if (!uECC_sign(sk, hash, 32, signature, curve)) {
		return 0;
	}
	
	// extract s from signature - (r, s) 
	uint8_t s[32];
	memcpy(s, &signature[32], 32); 
	
	// find lower-s if s is not already so
	if (big_int_greater_than_n(s, n_sp_div2, sizeof(s)) == 1) { // s is greater than n >> 1
		// replace s in signature with its additive inverse on the finite field
		uint8_t n[32]; // make copy of curve order because curve order is a constant variable
		memcpy(n, n_sp, 32);
		big_int_subtraction(s, n, &signature[32], sizeof(s));
	}
		
	return 1;
 }

uint16_t ed25519_sign(uint8_t *hash, uint8_t *sk, uint8_t *pk, uint8_t *signature) {
	Ed25519::sign(signature, sk, pk, hash, 32);
	return 1;
}

uint16_t secp256k1_verify(uint8_t *hash, uint8_t *pk, uint8_t *signature){
	uECC_set_rng(&RNG);
	const struct uECC_Curve_t * curve = uECC_secp256k1();
	uint16_t status = uECC_verify(pk, hash, 32, signature, curve);
	return status;
}

bool ed25519_verify(uint8_t *hash, uint8_t *pk, uint8_t *signature) {
	return Ed25519::verify(signature, pk, hash, 32);
}

int RNG(uint8_t *dest, unsigned int size) {
#if defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT)
   Cryptochip myChip(Wire, 0x60);
   if(!myChip.begin()) {
	   return 0; // error
   }
   myChip.random(dest, size);
#else
	// Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of 
  // random noise). This can take a long time to generate random data if the result of analogRead(0) 
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (uint16_t i = 0; i < 8; ++i) {
      uint16_t init = analogRead(0);
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }
      
      if (count == 0) {
         val = (val << 1) | (init & 0x01);
      } else {
         val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }

#endif
return 1;
}

uint16_t base58_encode_prefix_checksum(uint8_t *prefix, uint16_t prefixLength, uint8_t *data, uint16_t dataLength, uint8_t *b58str) {
	
	uint8_t message[prefixLength + dataLength + 4]; // prefix + data + checksum (4 bytes);
    memcpy(&message[0], &prefix[0], prefixLength);
    memcpy(&message[prefixLength], &data[0], dataLength);
    uint8_t sha256a[32];
    uint8_t sha256b[32]; // apply sha256 twice
    sha256_func_host(message, prefixLength+dataLength, sha256a);
    sha256_func_host(sha256a, 32, sha256b);
	memcpy(&message[prefixLength + dataLength], &sha256b[0], 4);
    
	char _buffer[100]; // signatures can have up to 98 or 99 chars with \0 at end
    memset(_buffer, '\0', 100);
    size_t outlength = base58_encode(message, sizeof(message), _buffer);
	memcpy(b58str, _buffer, outlength); 
	
	return outlength;
}

uint16_t base58_decode_prefix_checksum(uint16_t prefixLength, char *b58str, uint16_t b58strLength, uint8_t *data) {
	
	uint8_t _buffer[128]; // probably more than needed, sigs are at most 100 including the \0 char
	uint16_t dataLength = base58_decode(b58str, b58strLength, _buffer); // subtract one because the last character is the null character
	// the result has a prefix and four checksum bytes to be removed
	memcpy(data, &_buffer[prefixLength], dataLength - prefixLength - 4);
	return dataLength - prefixLength - 4;
}


uint8_t big_int_greater_than_n(uint8_t *s, const uint8_t *n, uint16_t n_bytes) {
    
    uint8_t greater_than_n = 0;
    
    // check each byte to see if s is less than n
    for (uint16_t i = 0; i < n_bytes; i++) {
        
        if (s[i] > n[i]) {
            greater_than_n = 1;
            break;
        }
        else if (s[i] < n[i]) {
            break;
        }
        else {
            // check next byte because equal condition on one byte is uncertain
        }
    }
 
    return greater_than_n; 
    
}

uint8_t big_int_subtraction(uint8_t *a, uint8_t *b, uint8_t *r, uint16_t n_bytes) {
	// calculates b minus a where both are large numbers represented as byte arrays
	// no checking is done but it is assumed that a is less than b
	// this will be used to find the additive inverse (in finite field) of signature values
	// that is, it will find lower-s for signatures using the secp256k1 curve
	
	// r = b - a where b > a
	uint16_t temp; // to hold currenty byte of b and borrow from next byte if necessary
	int i, j;
	for (i = n_bytes - 1; i >=0; i--) { // work through arrays right to left
		j = i;
		temp = b[i];
		if (a[i] > temp) { // need to borrow to subtract current bytes
			j--;
            while(b[j] == 0) { // next byte is zero so continue to next highest byte value
            	b[j] = 0xFF; // result of borrow
                j--;   
        	}
            b[j] = b[j] - 1; // borrow
            temp += 256; // and add here
		}
		r[i] = temp - a[i];
	}
	return 1;
}

uint32_t bigendian_bytes_to_uint32(uint8_t *byteArray) {

	uint32_t bigInt;

	bigInt = ((uint32_t)byteArray[0] << 24) | 
             ((uint32_t)byteArray[1] << 16) |
			 ((uint32_t)byteArray[2] << 8) |
			 ((uint32_t)byteArray[3]);

	return bigInt;

}