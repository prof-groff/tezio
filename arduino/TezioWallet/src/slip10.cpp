/* MIT License

Copyright (c) 2022 Jeffrey R. Groff

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

#include "slip10.h"

void seed_to_master_skcc(uint8_t *seed, uint16_t seed_length, uint8_t *master_skcc, uint8_t curve) {
	
	uint8_t hmac_key[16]; // enough space to hold any of the hmac keys
	uint16_t hmac_key_length;
	
	// the key to use with HMAC-SHA512 depends on the curve
	switch (curve){
		case SECP256K1: {
			hmac_key_length = sizeof(sp_hmac_key)-1;
			chars_to_bytes(sp_hmac_key, hmac_key_length, hmac_key);
			break;
		}
		case NISTP256: {
			hmac_key_length = sizeof(p2_hmac_key)-1;
			chars_to_bytes(p2_hmac_key, hmac_key_length, hmac_key);
			break;
		}
		case ED25519: {
			hmac_key_length = sizeof(ed_hmac_key)-1;
			chars_to_bytes(ed_hmac_key, hmac_key_length, hmac_key);
			break;
		}
	}
	
	// derive master key from seed
	hmac_sha512(hmac_key, hmac_key_length, seed, seed_length, master_skcc);
	while (1) {
		if(key_is_valid(master_skcc, 32, curve) == 1) {
			break;
		}
		else { // invalid key for the given curve - hash again
			uint8_t master_skcc_copy[64];
			memcpy(master_skcc_copy, master_skcc, 64);
			hmac_sha512(hmac_key, hmac_key_length, master_skcc_copy, 64, master_skcc);
		}
	}	
	return;
}

void seed_to_master_skcc(char *seed, uint16_t seed_length, uint8_t *master_skcc, uint8_t curve) {
	// seed_length is the number of characters in seed (including null char), not the number of bytes
	uint8_t seed_bytes[(seed_length-1)/2];
	hex_chars_to_byte_array(seed, seed_length, seed_bytes, sizeof(seed_bytes));
	seed_to_master_skcc(seed_bytes, sizeof(seed_bytes), master_skcc, curve);
	
	return;
}

void master_skcc_to_child_sk(uint8_t *master_skcc, char *path, uint16_t path_length, uint8_t *child_sk, uint8_t curve) {
	// path_length is the number of characters in path including null char
	
	uint8_t parent_skcc[64];
	uint8_t child_skcc[64];
	
	uint16_t n_indeces = derivation_path_preprocess(path, path_length);
	uint32_t indeces[n_indeces];
	derivation_path_to_indeces(path, path_length, indeces, n_indeces);
	
	memcpy(child_skcc, master_skcc, 64); 
  	for (uint16_t i = 0; i < n_indeces; i++) {
    	memcpy(parent_skcc, child_skcc, 64); // copy previous child to parent 
    	derive_child_skcc_from_parent(parent_skcc, indeces[i], child_skcc, curve);
	}
	
	memcpy(child_sk, child_skcc, 32);
	
	return;
	
}

void master_skcc_to_child_sk(uint8_t *master_skcc, char *path, uint16_t path_length, char *child_sk, uint8_t curve) {
	uint8_t child_sk_ba[32];
	master_skcc_to_child_sk(master_skcc, path, path_length, child_sk_ba, curve);
	byte_array_to_hex_chars(child_sk_ba, 32, child_sk, 65);
	
	return;
}


uint16_t derivation_path_preprocess(char *path, uint16_t path_length) {
  // parse the path to determine how many indeces it contains
  uint16_t n_indeces = 0;
  for (uint16_t i = 0; i < path_length-1; i++) {
    if (path[i] == '/') {
      n_indeces++;
    }
  }
  return n_indeces;
}

void derivation_path_to_indeces(char *path, uint16_t path_length, uint32_t *indeces, uint16_t n_indeces) {
  // convert path characters to numerical indeces
  bool parsing_index = false;
  uint16_t counter = 0;
  uint32_t index = 0;
  for (uint16_t i = 0; i < path_length-1; i++) {
    if (path[i] == '/' && parsing_index) { // end of index
      indeces[counter] = index; // save current index
      counter++; // increment counter
      index = 0; // reset index
    }
    else if (path[i] == '/' && !parsing_index) {
      parsing_index = true; // beginning first index
    }
    else if (parsing_index) {
      if (path[i] == '\'' || path[i] == 'h' || path[i] == 'H') {
        index += (uint32_t(1) << 31); // hardened
      }
      else {
        index = index * 10 + (path[i] - '0');
      }
    }
    else {
      // do nothing
    }
  }
  indeces[counter] = index;
}


uint16_t derive_child_skcc_from_parent(uint8_t *parent_skcc, uint32_t index, uint8_t *child_skcc, uint8_t curve) {
  uint8_t parent_sk[32]; // first half is secret key
  uint8_t parent_cc[32]; // second half is chain code
  memcpy(parent_sk, parent_skcc, 32); 
  memcpy(parent_cc, &parent_skcc[32], 32);
  
  uint8_t data[37]; // prefix byte + parent_sk + index (4 bytes)

  uint8_t index_bytes[4];
  memset(index_bytes, 0, 4);
  uint32_t temp_index = index;
  for (uint8_t i = 4; i > 0; i--) { // count backward, convert uint32_t to bigendian uint8_t array
    index_bytes[i-1] = (uint8_t)temp_index;
    temp_index = temp_index >> 8;
  }
  
  // form data to be hashed
  if (index < 0x80000000 && curve == ED25519) { 
      return 0; // error because Ed25519 does not support unhardend keys
  }
  else if (index < 0x80000000 && curve != ED25519) {
      // non-hardened key with curve secp256k1 or p256
      // data = compressed_public_point (concat) index
      uint8_t pk[64];
      derive_public_key(parent_sk, curve, pk);
      if (pk[63]%2 == 0) {
            data[0] = 0x02; // y coordinate is even
      }
      else {
          data[0] = 0x03; // y coordinate is odd
      }
      memcpy(&data[1], pk, 32);
      memcpy(&data[32+1], index_bytes, 4);
  }
  else { 
      // hardened key
      // data = 0x00 (concat) parent_sk (concat) index
    data[0] = 0x00;
    memcpy(&data[1], parent_sk, 32);
    memcpy(&data[1+32], index_bytes, 4);
  }

  
  // hash the data with HMAC-SHA512 using the parent chain code as the key
  hmac_sha512(parent_cc, 32, data, sizeof(data), child_skcc);
      
    
  // the result of this hash may not be the final child secret key and chain code
  // if the secp256k1 or the NIST P256 curve is used, the child sk is arrived at by adding the left part the hash to the parent key
  uint8_t LEFT[32]; // a place to hold on to the left part of the hash which is
    // about to be overwritten
  while(1) { 
    memcpy(LEFT, child_skcc, 32);
    finalize_child_skcc(child_skcc, parent_sk, curve);
      
  if (child_sk_is_valid(LEFT, child_skcc, curve) == 1){ // for the child secret key   to be valid both the original left portion of the hash must be less than n for the curve and the finalized child sk must not be zero
      break;
  }
      else { // redo the hash 
          data[0] = 0x01;
          memcpy(&data[1], &child_skcc[32], 32); // repeat hash using right portion of previous hash (chain code)
          memcpy(&data[33], &index_bytes[0], 4);
          hmac_sha512(parent_cc, 32, data, sizeof(data), child_skcc);
        }
    }
    
    return 1;
}


void finalize_child_skcc(uint8_t *child_skcc, uint8_t *parent_sk, uint8_t curve){
    // the final child key is the sum of the left part of the hash for a given index with the parent key
    const uint8_t *n;
    
    switch (curve) {
        case SECP256K1:
            {
                n = n_sp;
                break;
            }
        case NISTP256:
            {
                n = n_p2;
                break;
            }
        case ED25519:
            {
                return; // for ED25519 the result of the hash is the child key
            }
        default:
            {
                n = n_p2;
            }
    }
    uint8_t r[32]; // to hold result of modulo n addition
    
    add_bytes_modulo_n(child_skcc, parent_sk, n, r, 32);
    
    memcpy(child_skcc, r, 32);
    
    return;
    
}

uint16_t child_sk_is_valid(uint8_t *LEFT, uint8_t *child_skcc, uint8_t curve) {
    
    const uint8_t *n;
    
    switch (curve) {
        case ED25519:
            {
                return 1; // always valid
            }
        case NISTP256:
            {
                n = n_p2;
                break;
            }
        case SECP256K1:
            {
               n = n_sp;
               break;
            }
        default:
            {
                n = n_p2;
            }
    }
    
    if (key_less_than_order(LEFT, n, 32) == 1 && key_not_zero(child_skcc, 32) == 1) {
        return 1;
    }
    
    return 0;

}

uint8_t key_is_valid(uint8_t *sk, uint16_t n_bytes, uint8_t curve) {
    
    uint8_t valid = 0;
    
    const uint8_t *n;
    
    switch (curve) {
        case SECP256K1:
            {
                n = n_sp;
                break;
            }
        case NISTP256:
            {
                n = n_p2;
                break;
            }
        case ED25519:
            {
                valid = 1; // all keys are valid because the ED25519 library does a hash and handles key clamping (or so I think)
                return valid;
            }
        default:
            {
                n = n_p2;
            }
    }
    
    if(key_not_zero(sk, n_bytes) && key_less_than_order(sk, n, n_bytes)) {
        valid = 1;
    }
    
    return valid;
}


uint8_t key_not_zero(uint8_t *sk, uint16_t n_bytes) {
    
    uint8_t not_zero = 0;

    // check each byte looking for a value greater than zero
    for (uint16_t i = 0; i < n_bytes; i++) {
        
        if (sk[i] > 0) {
            not_zero = 1;
            break;
        }
        
    }
 
    return not_zero;
}

uint8_t key_less_than_order(uint8_t *sk, const uint8_t *n, uint16_t n_bytes) {
    
    uint8_t less_than_order = 0;
    
    // check each byte to see if key is less than n
    for (uint16_t i = 0; i < n_bytes; i++) {
        
        if (sk[i] < n[i]) {
            less_than_order = 1;
            break;
        }
        else if (sk[i] > n[i]) {
            break;
        }
        else {
            // check next byte because equal condition on one byte is uncertain
        }
    }
 
    return less_than_order; 
    
}

void add_bytes_modulo_n(uint8_t *a, uint8_t *b, const uint8_t *n, uint8_t *r, uint16_t n_bytes){
    // assumes a, b, an n are byte arrays with MSB first
    // adds and then reduces resulting in r
    uint16_t sum; // to hold sum of two bytes
    uint8_t carry = 0; // to hold carry if sum is larger than 0xFF
    
    uint8_t temp[n_bytes+1]; // to hold temporary result
    
    // calculate sum and store in temp (note that MSB in temp is one base-256 place larger than MSB in a and b)
    for (int i = n_bytes-1; i >=0; i--) {
        sum = a[i] + b[i] + carry;
        temp[i+1] = (uint8_t)sum;
        carry = (uint8_t)(sum >> 8); // same as division by 256
    }
    temp[0] = carry;
    
    // now reduce modulo n if result is greater than n. for this case it is
    // the same as subtracting n once
    if (temp[0] > 0 || key_less_than_order(&temp[1], n, n_bytes) == 0){
        int i, j;
        uint16_t diff; // to hold difference of two bytes
        
        for (i = sizeof(temp)-1; i > 0; i--) {
            j = i;
            diff = temp[i];
            if (temp[i] < n[i-1]) { // need to borrow to subtract
                j--;
                while(temp[j] == 0) { // next place value is zero so continue       to next highest place value
                    temp[j] = 0xFF; // result of borrow
                    j--;   
                }
                temp[j] = temp[j] - 1; // borrow
                diff += 256; // and add here
            }
            temp[i] = diff - n[i-1]; // do subtraction
        }
    }
    
    memcpy(r, &temp[1], n_bytes);
    
    return;
}

