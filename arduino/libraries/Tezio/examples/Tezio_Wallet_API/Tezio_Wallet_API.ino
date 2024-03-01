#include <TezioHSM_API.h>
#include "tests.h"

const uint8_t RWKey[32] = {0x93, 0x46, 0x63, 0xE3, 0xD4, 0xB4, 0x24, 0x62,
                           0x0B, 0xEA, 0x19, 0x7A, 0x73, 0xAD, 0x10, 0x54,
                           0x22, 0xA0, 0x19, 0x1A, 0x87, 0x79, 0xE6, 0x2C,
                           0xA4, 0x61, 0x26, 0x63, 0xA3, 0xF0, 0x99, 0xFB
                          };

bool debug = false; // put device in debug (interactive) mode and run tests
uint32_t baud = 57600;
TezioHSM_API myWallet(baud, RWKey); 


void setup() {

  if(!debug) {
    
    set_signing_policies(myWallet.policy);
    set_high_water_marks(myWallet.hwm); 

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
        	myWallet.send_error(INVALID_PACKET);
        	delay(1);
      	}
      	else if (myWallet.parse_message() == 0) {
        	// fail, send error code and proceed after short wait
        	myWallet.send_error(PARSE_ERROR);
        	delay(1);
		}
      	else if ((replyLength = myWallet.execute_op()) == 0) {
        	// failed to execute op command
        	myWallet.send_error(OP_ERROR);
        	delay(1);
      	}
      	else {
        	myWallet.send_reply(replyLength);
      	}
	}
  delay(1); // short wait
}
