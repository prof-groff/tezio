#include <TezioHSM_API.h>
#include "api_tests.h"
#include "secrets.h" // contains key for encrypted read/write operations
// #include "TezioHSM_Config.h"
// KEY ALIASES
#define TZ3_AUTH 0
#define TZ1 1
#define TZ2 2
#define TZ3 3

// MAGIC BYTES
#define LEGACY_BLOCK 0x01
#define LEGACY_ENDORSEMENT 0x02
#define TRANSFER 0x03
#define AUTHENTICATED_SIGNING_REQUEST 0x04
#define MICHELSON_DATA 0x05
#define BLOCK 0x11
#define PRE_ATTESTATION 0x12
#define ATTESTATION 0x13

bool debug = false; // put device in debug (interactive) mode and run tests
uint32_t baud = 57600;
TezioHSM_API myWallet(baud, RWKey); 

void setup() {

  if(!debug) {
    
    // set_signing_policies(myWallet.policy);
    // set_high_water_marks(myWallet.hwm); 
    myWallet.enable_signing(TZ3, BLOCK);
    myWallet.enable_signing(TZ3, PRE_ATTESTATION);
    myWallet.enable_signing(TZ3, ATTESTATION);

    myWallet.set_level_hwm(TZ3, BLOCK, 0);
    myWallet.set_level_hwm(TZ3, PRE_ATTESTATION, 0);
    myWallet.set_level_hwm(TZ3, ATTESTATION, 0); 
    
    myWallet.set_round_hwm(TZ3, BLOCK, 0);
    myWallet.set_round_hwm(TZ3, PRE_ATTESTATION, 0);
    myWallet.set_round_hwm(TZ3, ATTESTATION, 0);

  }

  else { // run some test
    
    // TezioHSM_API myWallet(baud, RWKey); 
    
    Serial.println("-- Testing Public Key Retrieval (op_get_pk, 0x11) --"); Serial.println();
    
    Serial.println("-- Raw Bytes --"); Serial.println();
    run_op_get_pk_test(myWallet, ED25519, 0x01);
    run_op_get_pk_test(myWallet, SECP256K1, 0x01);
    run_op_get_pk_test(myWallet, NISTP256, 0x01);
    run_op_get_pk_test(myWallet, NISTP256_AUTH, 0x01);
    
    Serial.println(); Serial.println("-- Compressed --"); Serial.println();
    run_op_get_pk_test(myWallet, ED25519, 0x02);
    run_op_get_pk_test(myWallet, SECP256K1, 0x02);
    run_op_get_pk_test(myWallet, NISTP256, 0x02);
    run_op_get_pk_test(myWallet, NISTP256_AUTH, 0x02);
    
    Serial.println(); Serial.println("-- Base58 Checksum Encoded --"); Serial.println();
    run_op_get_pk_test(myWallet, ED25519, 0x03);
    run_op_get_pk_test(myWallet, SECP256K1, 0x03);
    run_op_get_pk_test(myWallet, NISTP256, 0x03);
    run_op_get_pk_test(myWallet, NISTP256_AUTH, 0x03);
    
    Serial.println(); Serial.println("-- Tezos Public Key Hash (Address) --"); Serial.println();
    run_op_get_pk_test(myWallet, ED25519, 0x04);
    run_op_get_pk_test(myWallet, SECP256K1, 0x04);
    run_op_get_pk_test(myWallet, NISTP256, 0x04);
    run_op_get_pk_test(myWallet, NISTP256_AUTH, 0x04);

    Serial.println();
    Serial.println("-- Testing Message Signing and Signature Verification (op_sign, 0x21; op_verify, 0x22) --"); Serial.println();
    
    Serial.println(); Serial.println("-- Message Hashed, Signature Raw Bytes --");
    run_op_sign_and_verify_test(myWallet, ED25519, 0x01);
    run_op_sign_and_verify_test(myWallet, SECP256K1, 0x01);
    run_op_sign_and_verify_test(myWallet, NISTP256, 0x01);
    run_op_sign_and_verify_test(myWallet, NISTP256_AUTH, 0x01);

    Serial.println(); Serial.println("-- Message Hashed, Signature Base58 Checksum Encoded --");
    run_op_sign_and_verify_test(myWallet, ED25519, 0x02);
    run_op_sign_and_verify_test(myWallet, SECP256K1, 0x02);
    run_op_sign_and_verify_test(myWallet, NISTP256, 0x02);
    run_op_sign_and_verify_test(myWallet, NISTP256_AUTH, 0x02);

    Serial.println(); Serial.println("-- Message Unhashed, Signature Raw Bytes --");
    run_op_sign_and_verify_test(myWallet, ED25519, 0x03);
    run_op_sign_and_verify_test(myWallet, SECP256K1, 0x03);
    run_op_sign_and_verify_test(myWallet, NISTP256, 0x03);
    run_op_sign_and_verify_test(myWallet, NISTP256_AUTH, 0x03);

    Serial.println(); Serial.println("-- Message Unhashed, Signature Base58 Checksum Encoded --");
    run_op_sign_and_verify_test(myWallet, ED25519, 0x04);
    run_op_sign_and_verify_test(myWallet, SECP256K1, 0x04);
    run_op_sign_and_verify_test(myWallet, NISTP256, 0x04);
    run_op_sign_and_verify_test(myWallet, NISTP256_AUTH, 0x04);
  }
}
  
void loop() {
	
	if(!debug) {
		
		// TezioHSM_API myWallet(baud, RWKey); 
		
		uint16_t packetLength, replyLength;

		myWallet.wait_for_start_byte();
		// packetLength = myWallet.read_packet();
    myWallet.read_packet();
      	if (myWallet.validate_packet() == 0) {
        	// fail, send error code and proceed after short wait
        	myWallet.send_status_code();
        	delay(1);
      	}
      	else if (myWallet.parse_message() == 0) {
        	// fail, send error code and proceed after short wait
        	myWallet.send_status_code();
        	delay(1);
		}
      	else if (myWallet.execute_op() == 0) {
        	// failed to execute op command
        	myWallet.send_status_code();
        	delay(1);
      	}
      	else {
        	myWallet.send_reply();
      	}
	}
  delay(1); // short wait
}
