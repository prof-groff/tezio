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

#include "TezioWallet_Setup.h"

uint16_t TezioWallet_Setup::configure(const uint8_t *configData) {
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
    	Serial.println("The cryptochips's configuration data is already locked and can't be changed."); Serial.println(); delay(1000);
	}
	
	// a chance to view the configuration data written to the cryptographic co-processor.
	Serial.println("Do you wish to view the cryptochips current configuration data?"); Serial.println(); delay(1000); 
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
    	Serial.println("Do you wish to lock the configuration data zone?"); 
    	if (confirm_entry()) {
			if (!myChip.lockConfigZone()) {
        	Serial.println("ERROR: Failed to lock the configuration zone.");
        	wait_forever();
      		}
      		else {
        		Serial.println("Configuration zone locked successfully."); Serial.println(); delay(SHORTWAIT);
	  		}
		}
    	else {
      		Serial.println("Configuration zone remains unlocked but must be locked before provisioning.");
      		wait_forever();
    	}
	}
	
	myChip.end();
	return 1;
}

uint16_t TezioWallet_Setup::check_mnemonic(char *mnemonic, uint16_t mnemonic_length) {
	
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

uint16_t TezioWallet_Setup::derive_keys(char *path, uint16_t path_length, char* password, uint16_t password_length) {
	start_serial();
	Serial.println("-- Deriving Keys from Mnemonic --"); Serial.println(); delay(1000);
	
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

uint16_t TezioWallet_Setup::provision(const uint8_t *RWKey) {
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
		Serial.println("ERROR: The data/OTP zones are already locked. New data can't be written."); wait_forever();
	}
	
	// try writing P2Key (PrivWrite)
	uint8_t padded_p2sk[36]; 
	memset(padded_p2sk, 0x00, 36); 
	memcpy(&padded_p2sk[4], p2sk, 32); // pad with 4 leading bytes of zeros
	if(!myChip.privWriteSlot(P2_SK_SLOT, padded_p2sk, sizeof(padded_p2sk))) {
		Serial.println("ERROR: Failed to write NistP256 secret key."); Serial.println(); delay(SHORTWAIT);
	}
	// try writing EDKey and SPKey (Write)
	if (!myChip.writeSlot(ED_SK_SLOT, edsk, 32)) {
		Serial.println("ERROR: Failed to write Ed25519 secret key."); Serial.println(); delay(SHORTWAIT);
	}
	if (!myChip.writeSlot(SP_SK_SLOT, spsk, 32)) {
		Serial.println("ERROR: Failed to write Secp256K1 secret key."); Serial.println(); delay(SHORTWAIT);
	}
	
	// try to write RWKey (write)
	if (!myChip.writeSlot(RW_KEY_SLOT, RWKey, 32)) {
		Serial.println("ERROR: Failed to write read/write key."); Serial.println(); delay(SHORTWAIT);
	}
	
	// try to write public keys
	if (!myChip.writeSlot(ED_PK_SLOT, edpk, 32)) {
		Serial.println("ERROR: Failed to write Ed25519 public key."); Serial.println(); delay(SHORTWAIT);
	}
	if (!myChip.writeSlot(SP_PK_SLOT, sppk, 64)) {
		Serial.println("ERROR: Failed to write Secp256K1 public key."); Serial.println(); delay(SHORTWAIT);
	}
	if (!myChip.writeSlot(P2_PK_SLOT, p2pk, 64)) {
		Serial.println("ERROR: Failed to write NistP256 public key."); Serial.println(); delay(SHORTWAIT);
	}
	
	Serial.println("Do you wish to lock the cryptochip data zone? Modifying keys with clear writes will no longer be possible."); Serial.println(); delay(SHORTWAIT);
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
	
	return 1;

}



TezioWallet_Setup::TezioWallet_Setup() {
	
	
}