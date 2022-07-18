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

void generate_entropy(uint8_t *entropy, uint16_t entropy_length) {
    randomSeed(analogRead(0)); // try to get some randomness from the system
    for (uint16_t i = 0; i < entropy_length; i ++) {
        entropy[i] = random(0, 256); 
    }
    
	return;
}