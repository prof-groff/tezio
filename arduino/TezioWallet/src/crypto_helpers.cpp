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

void compress_public_key(uint8_t *pk, uint curve, uint8_t *cpk) {
	
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
    size_t outlength = base58_func(tzaddress, sizeof(tzaddress), _buffer);
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
    uint16_t outLength = base58_func(pkBase58, sizeof(pkBase58), _buffer);
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
    size_t outlength = base58_func(message, sizeof(message), _buffer);
	memcpy(b58str, _buffer, outlength); 
	
	return outlength;
}

uint16_t base58_decode_prefix_checksum(uint16_t prefixLength, char *b58str, uint16_t b58strLength, uint8_t *data) {
	
	uint8_t _buffer[128]; // probably more than needed, sigs are at most 100 including the \0 char
	uint16_t dataLength = base58_decode_func(b58str, b58strLength - 1, _buffer); // subtract one because the last character is the null character
	// the result has a prefix and four checksum bytes to be removed
	memcpy(data, &_buffer[prefixLength], dataLength - prefixLength - 4);
	return dataLength - prefixLength - 4;
}