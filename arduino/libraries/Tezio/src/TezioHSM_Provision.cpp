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

#include "TezioHSM_Provision.h"

uint16_t TezioHSM_Provision::write_p256_secret_key(uint8_t slot, uint8_t *p2sk, const uint8_t *RWKey) {

	// received 32 byte key in raw bytes and writes to slot 0 to 4
	
	Cryptochip myChip(Wire, 0x60);
	
	uint8_t sessionKey[32];
	uint8_t cypherText[36];
	
	// verify that a cryptochip is on the bus
  	if(!myChip.begin()) {
    	Serial.println("ERROR: Cryptochip not detected."); 
    	wait_forever();
  	}
	
	// pad ps2k with leading zeros so data is 36 bytes
	uint8_t P2SecretKey[36];
	memset(P2SecretKey, 0, 36);
	memcpy(&P2SecretKey[4], p2sk, 32);
			
	// generate sessionKey
	if (!myChip.generateSessionKey(RW_KEY_SLOT, RWKey, sessionKey)){
		return 0;
	}
	
	// use sessionKey to generate cypherText
	if (!myChip.encryptData(P2SecretKey, cypherText, 36)) { // 36 bytes
		return 0;
	}
			
	// compute expected MAC
	//  MAC is SHA-256 Hash of message = sessionkey | privwrite opcode 0x46 | param1 0x40 | param2 2 byte key slot LSB first | SN[8] | SN[0:1] | Zeros(21) | 36 bytes of Plaintext
  	uint16_t messageLength = 32 + 1 + 1 + 2 + 1 + 2 + 21 + 36; // 96
  	uint8_t message[messageLength];
  	memcpy(&message[0], &sessionKey[0], 32);
  	message[32] = 0x46;
  	message[33] = 0x40;
	message[34] = (uint8_t)(slot);
  	message[35] = 0x00; // lsb comes first, msb ignored
  	uint8_t sn[12];
  	myChip.serialNumber(sn);
  	message[36] = sn[8];
  	message[37] = sn[0];
  	message[38] = sn[1];
  	uint8_t zeros[21];
  	memset(zeros, 0, 21);
  	memcpy(&message[39], &zeros[0], 21);
  	memcpy(&message[60], &P2SecretKey[0], 36);

  	uint8_t mac[32];
  	sha256_func_host(message, messageLength, mac);
  
	// try encrypted private write of secret key
	uint8_t data[68]; // 36 bytes of cyphertext and 32 byte mac
	memcpy(&data[0], cypherText, 36);
	memcpy(&data[36], mac, 32);
	if (!myChip.encryptedPrivWrite(slot, data, sizeof(data))) {
		Serial.println("ERROR: Failed to write NIST P256 secret key."); Serial.println(); delay(SHORTWAIT);
		return 0;
	}

	myChip.end();
	
	return 1;

}

uint16_t TezioHSM_Provision::write_secret_key(uint8_t slot, uint8_t *sk, const uint8_t *RWKey) {

	Cryptochip myChip(Wire, 0x60);
	
	// verify that a cryptochip is on the bus
  	if(!myChip.begin()) {
    	Serial.println("ERROR: Cryptochip not detected."); 
    	wait_forever();
  	}

	// generate sessionKey
	uint8_t sessionKey[32];
	uint8_t cypherText[32];

	if (!myChip.generateSessionKey(RW_KEY_SLOT, RWKey, sessionKey)){
		return 0;
	}
	
	// use sessionKey to generate cypherText
	if (!myChip.encryptData(sk, cypherText, 32)) {
		return 0;
	}
			
	
	// compute expected MAC
	// MAC is SHA256 Hash of message = sessionkey | write opcode 0x12 | param1 0x82 | param2 address | SN[8] | SN[0:1] | Zeros(25) | Plaintext
  	uint16_t messageLength = 32 + 1 + 1 + 2 + 1 + 2 + 25 + 32; // 96
  	uint8_t message[messageLength];
  	memcpy(&message[0], &sessionKey[0], 32);
  	message[32] = 0x12;
  	message[33] = 0x82;
  	uint16_t address = myChip.addressForSlotOffset(slot, 0);
  	message[34] = (uint8_t)(address);
  	message[35] = (uint8_t)(address >> 8); // lsb comes first
  	uint8_t sn[12];
  	myChip.serialNumber(sn);
  	message[36] = sn[8];
  	message[37] = sn[0];
  	message[38] = sn[1];
  	uint8_t zeros[25];
  	memset(zeros, 0, 25);
  	memcpy(&message[39], &zeros[0], 25);
  	memcpy(&message[64], &sk[0], 32);

  	uint8_t mac[32];
  	sha256_func_host(message, messageLength, mac);
  
	// try encrypted write of secret key
	if (!myChip.encryptedWrite(slot, cypherText, mac, 32)) {
		return 0;
	}
	
	myChip.end();
	return 1;

}




uint16_t TezioHSM_Provision::configure(const uint8_t *configData) {
	start_serial();
	Cryptochip myChip(Wire, 0x60);
	
  	Serial.println("-- Configuring Cryptographic Coprocessor --"); Serial.println(); delay(SHORTWAIT);
	
	// verify that a cryptochip is on the bus
  	if(!myChip.begin()) {
    	Serial.println("ERROR: Cryptochip not detected."); 
    	wait_forever();
  	}
 
 	 // check cryptochip lock status
  	uint8_t lock_status[2];
  	if (!myChip.locked(lock_status)) {
    	Serial.println("ERROR: Failed to determine cryptochip lock status. Configuration data can't be written.");
    	wait_forever();
  	}
	if (lock_status[1] == 0) { // configuration zone is unlocked
    	if (!myChip.writeConfiguration(configData)) {
      		Serial.println("ERROR: Failed to write configuration data.");
      		wait_forever();
    	}
    	else { 
      		Serial.println("Configuration data successfully written to cryptochip."); Serial.println(); delay(SHORTWAIT);
    	}
  	}
  	else if (lock_status[1] == 1) { // configuration zone is already locked, continue...
    	Serial.println("The cryptochips's configuration data is already locked and can't be changed."); Serial.println(); delay(SHORTWAIT);
	}
	
	// a chance to view the configuration data written to the cryptographic co-processor.
	Serial.println("Do you wish to view the cryptochips current configuration data?"); Serial.println(); delay(SHORTWAIT); 
	if (confirm_entry()) {
		uint8_t currentConfigData[128];
  		Serial.println(); Serial.println("Reading current configuration data."); Serial.println(); delay(SHORTWAIT);
  		if (!myChip.readConfiguration(currentConfigData)) {
    		Serial.println("ERROR: Failed to read configuration data.");
    		wait_forever();
  		}
  		else {
    		print_hex_data(currentConfigData, sizeof(currentConfigData)); Serial.println(); delay(SHORTWAIT);
  		}
	}
	else {
		Serial.println();
	}
	
	// a chance to lock the configuration zone
	if (lock_status[1] == 0) {
    	Serial.println("Do you wish to lock the configuration data zone?"); Serial.println(); delay(SHORTWAIT);
    	if (confirm_entry()) {
			Serial.println();
			if (!myChip.lockConfigZone()) {
        	Serial.println("ERROR: Failed to lock the configuration zone.");
        	wait_forever();
      		}
      		else {
        		Serial.println("Configuration zone locked successfully."); Serial.println(); delay(SHORTWAIT);
	  		}
		}
    	else {
			Serial.println();
      		Serial.println("Configuration zone remains unlocked but must be locked before provisioning.");
      		wait_forever();
    	}
	}
	
	myChip.end();
	return 1;
}

uint16_t TezioHSM_Provision::check_mnemonic(char *mnemonic, uint16_t mnemonic_length) {
	
	if (strcmp(mnemonic, "") == 0) {
		Serial.println("No mnemonic was provided so one will be generated."); Serial.println(); delay(SHORTWAIT);
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin()) {
			Serial.println("ERROR: Entropy can't be generated because a cryptographic co-processor was not detected on the connected device.");
			wait_forever();
		}
		uint8_t lock_status[2];
		if (!myChip.locked(lock_status)) {
			Serial.println("ERROR: Failed to determine cryptographic co-processor lock status. Entropy can't be generated.");
			wait_forever();
		}
		if (lock_status[1] == 0) {
    		Serial.println("ERROR: The cryptographic co-processor's configuration zone must be locked before the onboard random number generator can be used."); 
    		wait_forever();
  		}
		else if (lock_status[1] == 1) {
			uint8_t entropy[32]; 
			if (!myChip.random(entropy, sizeof(entropy))) {
				Serial.println("ERROR: Failed to generate entropy.");
				wait_forever();
			}
			else {
				char new_mnemonic[24][10]; 
				entropy_to_mnemonic(entropy, sizeof(entropy), new_mnemonic);
				mnemonicStringLength = mnemonic_to_string(new_mnemonic, 24, mnemonicString);
				Serial.println("Write down the following 24 word mnemonic phrase and keep it secret and safe."); Serial.println(); delay(SHORTWAIT);
				Serial.println(mnemonicString); Serial.println(); delay(SHORTWAIT);
				confirm_continue();
			}
		}
		myChip.end();
		
	}
	else {
		uint16_t valid = validate_mnemonic_string(mnemonic, mnemonic_length); // validate mnemonic passed to function
		if (valid == 0) {
			Serial.println("ERROR: The provided mnemonic phrase is invalid. Please verify.");
			wait_forever(); 
		}
		else {
			memcpy(mnemonicString, mnemonic, mnemonic_length);
			mnemonicStringLength = mnemonic_length;
		}
	}
	return 1;
}

uint16_t TezioHSM_Provision::derive_keys(char *path, uint16_t path_length, char* password, uint16_t password_length) {
	start_serial();
	Serial.println("-- Deriving Keys from Mnemonic --"); Serial.println(); delay(SHORTWAIT);
	
	// derive secret master seed from mnemonic phrase
	uint8_t seed[64]; 
	mnemonic_string_to_seed(mnemonicString, mnemonicStringLength, seed, password, password_length, 2048);
	
	// derive secret private key and public key (compressed if applicable) for each curve;
	uint8_t master_skcc[64];
	// uint8_t public_key[64]; 
	
	// ed25519 curve
	seed_to_master_skcc(seed, sizeof(seed), master_skcc, ED25519);
	master_skcc_to_child_sk(master_skcc, path, path_length, edsk, ED25519);
	derive_public_key(edsk, ED25519, edpk); // Ed25519 public keys are only 32 bytes
	
	
	// secp256k1 curve
	seed_to_master_skcc(seed, sizeof(seed), master_skcc, SECP256K1);
	master_skcc_to_child_sk(master_skcc, path, path_length, spsk, SECP256K1);
	derive_public_key(spsk, SECP256K1, sppk);
	
	// NIST P256 curve
	seed_to_master_skcc(seed, sizeof(seed), master_skcc, NISTP256);
	master_skcc_to_child_sk(master_skcc, path, path_length, p2sk, NISTP256);
	derive_public_key(p2sk, NISTP256, p2pk);
	
	return 1;
	
}

uint16_t TezioHSM_Provision::provision(const uint8_t *RWKey, char *authKey) {
	start_serial();
	Serial.println("-- Provisioning Cryptochip --"); Serial.println(); delay(SHORTWAIT);
	
	Cryptochip myChip(Wire, 0x60);
	if (!myChip.begin()) {
		Serial.println("ERROR: No cryptographic co-processor detected.");
		wait_forever();
	}
	
 	// retrieve chip lock_status - [0] data/OTP zone, [1] configuration zone
  	uint8_t lock_status[2];
  	if (!myChip.locked(lock_status)) {
    	Serial.println("ERROR: Failed to determine cryptochip lock status. Data can't be written.");
    	wait_forever();
  	}
	
	if (lock_status[0] == 1) {
		Serial.println("The data/OTP zones are already locked and may already contain keys. Do you wish to continue?"); 
		Serial.println("NOTE: Continuing will overwrite existing keys and requires the use of the read/write key already saved on the HSM."); 
		Serial.println("Failure to use the same read/write key will result in failure to write new keys."); Serial.println(); delay(SHORTWAIT);
		if (confirm_entry()) {

			write_p256_secret_key(P2_SK_SLOT, p2sk, RWKey);
	
			// try clear write of public key
			if (!myChip.writeSlot(P2_PK_SLOT, p2pk, 64)) { // P2 public keys are 64 bytes (uncompressed)
				Serial.println("ERROR: Failed to write NIST P256 public key."); Serial.println(); delay(SHORTWAIT);
				return 0;
			}

			// write SP key
			if (!write_secret_key(SP_SK_SLOT, spsk, RWKey)) {
				Serial.println("ERROR: Failed to write Secp256k1 secret key."); Serial.println(); delay(SHORTWAIT);
				return 0;
			}
	
			// try clear write of public key
			if (!myChip.writeSlot(SP_PK_SLOT, sppk, 64)) { // SP public keys are 64 bytes (uncompressed)
				Serial.println("ERROR: Failed to write Secp256k2 public key."); Serial.println(); delay(SHORTWAIT);
				return 0;
			}
		
			// write ED key
			if (!write_secret_key(ED_SK_SLOT, edsk, RWKey)) {
				Serial.println("ERROR: Failed to write Ed25519 secret key."); Serial.println(); delay(SHORTWAIT);
				return 0;
			}

			// try clear write of public key
			if (!myChip.writeSlot(ED_PK_SLOT, edpk, 32)) { // ED public keys are 32 bytes
				Serial.println("ERROR: Failed to write Ed25519 public key."); Serial.println(); delay(SHORTWAIT);
				return 0;
			}

		}
		else {
			Serial.println("New keys will not be written to the device."); Serial.println(); delay(SHORTWAIT);
			wait_forever();
		}
	Serial.println(); Serial.println("New keys successfully written to the device."); Serial.println(); delay(SHORTWAIT);
		
	}
		
	else {
	
		// try writing P2Key (PrivWrite)
		uint8_t padded_p2sk[36]; 
		memset(padded_p2sk, 0x00, 36); 
		memcpy(&padded_p2sk[4], p2sk, 32); // pad with 4 leading bytes of zeros so onboard hardware acceleration of cryptographic calculations works correctly
		if(!myChip.privWriteSlot(P2_SK_SLOT, padded_p2sk, sizeof(padded_p2sk))) {
			Serial.println("ERROR: Failed to write NistP256 secret key."); Serial.println(); delay(SHORTWAIT);
			return 0;
		}
		// try writing EDKey and SPKey (Write)
		if (!myChip.writeSlot(ED_SK_SLOT, edsk, 32)) {
			Serial.println("ERROR: Failed to write Ed25519 secret key."); Serial.println(); delay(SHORTWAIT);
			return 0;
		}
		if (!myChip.writeSlot(SP_SK_SLOT, spsk, 32)) {
			Serial.println("ERROR: Failed to write Secp256K1 secret key."); Serial.println(); delay(SHORTWAIT);
			return 0;
		}
	
		// try to write RWKey (write)
		if (!myChip.writeSlot(RW_KEY_SLOT, RWKey, 32)) {
			Serial.println("ERROR: Failed to write read/write key."); Serial.println(); delay(SHORTWAIT);
			return 0;
		}
	
		// try to write public keys
		if (!myChip.writeSlot(ED_PK_SLOT, edpk, 32)) {
			Serial.println("ERROR: Failed to write Ed25519 public key."); Serial.println(); delay(SHORTWAIT);
			return 0;
		}
		if (!myChip.writeSlot(SP_PK_SLOT, sppk, 64)) {
			Serial.println("ERROR: Failed to write Secp256K1 public key."); Serial.println(); delay(SHORTWAIT);
			return 0;
		}
		if (!myChip.writeSlot(P2_PK_SLOT, p2pk, 64)) {
			Serial.println("ERROR: Failed to write NistP256 public key."); Serial.println(); delay(SHORTWAIT);
			return 0;
		}
	
		Serial.println("Do you wish to lock the cryptochip data zone? Modifying keys with unencrypted writes will no longer be possible."); Serial.println(); delay(SHORTWAIT);
  		if (confirm_entry()) {
    		if (!myChip.lockDataOTPZones()) {
      			Serial.println("ERROR: Failed to lock the data zone.");
      			wait_forever();
    		}
    		else {
      			Serial.println(); Serial.println("Data zone locked successfully."); Serial.println(); delay(SHORTWAIT);
    		}
  		}
  		else {
    		Serial.println(); Serial.println("Data zone remains unlocked. It must be locked before use."); wait_forever();
  		}
  		
  	}
  	
  	
  	// Last step is to write a second P256 key. If none is provided, one is generated and shared. 
	// It is stored on slot 0 and can be used to validate messages. It is NOT used for a tz address.
  	Serial.println("Preparing to write authentication key."); Serial.println(); delay(SHORTWAIT);
	if (strcmp(authKey, "") == 0) {
		// no authKey was provided so one will be generated and printed.
		Serial.println("No authentication key was provided. Do you wish to generate a new authenticating key?"); Serial.println(); delay(SHORTWAIT); 
		if (confirm_entry()) {
	
			Serial.println("--Generating Authentication Secret--");
  	
			if (!myChip.locked(lock_status)) {
				Serial.println("ERROR: Failed to determine cryptographic co-processor lock status. Entropy can't be generated.");
				wait_forever();
			}
			if (lock_status[1] == 0) {
    			Serial.println("ERROR: The cryptographic co-processor's configuration zone must be locked before the onboard random number generator can be used."); 
    			wait_forever();
  			}
			else if (lock_status[1] == 1) { 
				if (!myChip.random(p2sk_auth, SK_SIZE)) {
					Serial.println("ERROR: Failed to generate entropy.");
					return 0;
				}
			}

			Serial.println("Authentication secret key created. Please record the following in a safe and secret location."); Serial.println(); delay(SHORTWAIT); 
  			char skb58[99];
  			uint16_t outlength = secret_key_base58(p2sk_auth, NISTP256_AUTH, skb58);
  			Serial.println('--Secret Auth Key--');
  			Serial.println(skb58);
		}
		else {
			Serial.println("ERROR: Failed to finish writing authentication key.");
			wait_forever();
		}
	}
	else { // auth key was provided
				 
		base58_decode_prefix_checksum(N_SK_PREFIX_BYTES, authKey, P2_B58CHECKSUM_SK_SIZE+1, p2sk_auth); // sk prefix length is 4 for all curves
		// add 1 to key size because there is a null character at the end
	}

	derive_public_key(p2sk_auth, NISTP256, p2pk_auth);

	if (!write_p256_secret_key(P2_AUTH_KEY_SLOT, p2sk_auth, RWKey)) {
  		Serial.println('ERROR: Failed to write authentication key to slot 0');
  		return 0;
  	}
	
	// write public key to slot
	if (!myChip.writeSlot(P2_AUTH_KEY_PK_SLOT, p2pk_auth, P2_PK_SIZE)) {
			Serial.println("ERROR: Failed to write authentication public key."); Serial.println(); delay(SHORTWAIT);
			return 0;
	}

	// print PKHs
	uint8_t pk_pkh_buffer[64]; // to hold pk and pkh
	char pkh[37]; // extra space for null terminator
	uint16_t pkhLength;

	Serial.println("Key derivation and provisioning completed succcessfully."); Serial.println(); delay(SHORTWAIT);
	Serial.println("Stored keys derived from the mnemonic phrase correspond to the following Tezos addresses."); Serial.println(); delay(SHORTWAIT);
	
	Serial.println("-- ED25519 Public Key Hash --"); Serial.println(); delay(SHORTWAIT);
	memcpy(pk_pkh_buffer, edpk, ED_PK_SIZE);
	pkhLength = encode_public_key(pk_pkh_buffer, ED_PK_SIZE, PKH_BASE58_CHECKSUM, ED25519);
	memset(pkh, '\0', 37); 
	memcpy(pkh, pk_pkh_buffer, pkhLength);
	Serial.println(pkh); Serial.println(); delay(SHORTWAIT);

	Serial.println("-- SECP256K1 Public Key Hash --"); Serial.println(); delay(SHORTWAIT);
	memcpy(pk_pkh_buffer, sppk, SP_PK_SIZE);
	pkhLength = encode_public_key(pk_pkh_buffer, SP_PK_SIZE, PKH_BASE58_CHECKSUM, SECP256K1);
	memset(pkh, '\0', 37); 
	memcpy(pkh, pk_pkh_buffer, pkhLength);
	Serial.println(pkh); Serial.println(); delay(SHORTWAIT);
	
	Serial.println("-- NIST P256 Public Key Hash --"); Serial.println(); delay(SHORTWAIT);
	memcpy(pk_pkh_buffer, p2pk, P2_PK_SIZE);
	pkhLength = encode_public_key(pk_pkh_buffer, P2_PK_SIZE, PKH_BASE58_CHECKSUM, NISTP256);
	memset(pkh, '\0', 37); 
	memcpy(pkh, pk_pkh_buffer, pkhLength);
	Serial.println(pkh); Serial.println(); delay(SHORTWAIT);
	
	return 1;
}



TezioHSM_Provision::TezioHSM_Provision() {
	
	
}