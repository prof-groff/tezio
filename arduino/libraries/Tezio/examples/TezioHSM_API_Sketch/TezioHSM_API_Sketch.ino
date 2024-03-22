#include <TezioHSM_API.h>
#include "api_tests.h"
#include "secrets.h" // contains key for encrypted read/write operations

// CURVE/SLOT/KEY ALIASES
#define TZ3_AUTH 0
#define TZ1 1
#define TZ2 2
#define TZ3 3

// HSM OPERATIONS
#define OP_GET_PK 0x11
#define OP_SIGN 0x21
#define OP_VERIFY 0x22
#define OP_WRITE_KEYS 0x31

// TEZOS OPERATIONS MAGIC BYTES
#define LEGACY_BLOCK 0x01
#define LEGACY_ENDORSEMENT 0x02
#define TRANSFER 0x03
#define AUTHENTICATED_SIGNING_REQUEST 0x04
#define MICHELSON_DATA 0x05
#define BLOCK 0x11
#define PRE_ATTESTATION 0x12
#define ATTESTATION 0x13

// OP_GET_PK RETURNED KEY FORMATS
#define PK_RAW_BYTES 0x01
#define PK_COMPRESSED_BYTES 0x02
#define PK_BASE58_CHECKSUM_ENCODED 0x03
#define PKH_TEZOS_ADDRESS 0x04

// OP_SIGN AND OP_VERIFY MESSAGE AND SIGNATURE FORMATS
#define MESSAGE_HASHED_SIG_RAW_BYTES 0x01
#define MESSAGE_HASHED_SIG_BASE58_CHECKSUM_ENCODED 0x02
#define MESSAGE_UNHASHED_SIG_RAW_BYTES 0x03
#define MESSAGE_UNHASHED_SIG_BASE58_CHECKSUM_ENCODED 0x04
  
bool debug = false; // true puts device in interactive mode and runs tests
uint32_t baud = 57600;
TezioHSM_API myHSM(baud, RWKey); 

void setup() {

  if(!debug) {
    
    myHSM.enable_tezos_op(TZ3, BLOCK);
    myHSM.enable_tezos_op(TZ3, PRE_ATTESTATION);
    myHSM.enable_tezos_op(TZ3, ATTESTATION);

    myHSM.disable_hsm_op(TZ3_AUTH, OP_SIGN);
    myHSM.disable_hsm_op(TZ1, OP_SIGN);
    myHSM.disable_hsm_op(TZ2, OP_SIGN);

    myHSM.disable_hsm_op(TZ3_AUTH, OP_WRITE_KEYS);
    myHSM.disable_hsm_op(TZ1, OP_WRITE_KEYS);
    myHSM.disable_hsm_op(TZ2, OP_WRITE_KEYS);
    myHSM.disable_hsm_op(TZ3, OP_WRITE_KEYS);

    myHSM.set_level_hwm(TZ3, BLOCK, 0);
    myHSM.set_level_hwm(TZ3, PRE_ATTESTATION, 0);
    myHSM.set_level_hwm(TZ3, ATTESTATION, 0); 
    
    myHSM.set_round_hwm(TZ3, BLOCK, 0);
    myHSM.set_round_hwm(TZ3, PRE_ATTESTATION, 0);
    myHSM.set_round_hwm(TZ3, ATTESTATION, 0);

  }

  else { // run some test
    
    Serial.println("-- Testing Public Key Retrieval (op_get_pk, 0x11) --"); Serial.println();
    
    Serial.println("-- Raw Bytes --"); Serial.println();
    run_op_get_pk_test(myHSM, TZ1, PK_RAW_BYTES);
    run_op_get_pk_test(myHSM, TZ2, PK_RAW_BYTES);
    run_op_get_pk_test(myHSM, TZ3, PK_RAW_BYTES);
    run_op_get_pk_test(myHSM, TZ3_AUTH, PK_RAW_BYTES);
    
    Serial.println(); Serial.println("-- Compressed --"); Serial.println();
    run_op_get_pk_test(myHSM, TZ1, PK_COMPRESSED_BYTES);
    run_op_get_pk_test(myHSM, TZ2, PK_COMPRESSED_BYTES);
    run_op_get_pk_test(myHSM, TZ3, PK_COMPRESSED_BYTES);
    run_op_get_pk_test(myHSM, TZ3_AUTH, PK_COMPRESSED_BYTES);
    
    Serial.println(); Serial.println("-- Base58 Checksum Encoded --"); Serial.println();
    run_op_get_pk_test(myHSM, TZ1, PK_BASE58_CHECKSUM_ENCODED);
    run_op_get_pk_test(myHSM, TZ2, PK_BASE58_CHECKSUM_ENCODED);
    run_op_get_pk_test(myHSM, TZ3, PK_BASE58_CHECKSUM_ENCODED);
    run_op_get_pk_test(myHSM, TZ3_AUTH, PK_BASE58_CHECKSUM_ENCODED);
    
    Serial.println(); Serial.println("-- Tezos Public Key Hash (Address) --"); Serial.println();
    run_op_get_pk_test(myHSM, TZ1, PKH_TEZOS_ADDRESS);
    run_op_get_pk_test(myHSM, TZ2, PKH_TEZOS_ADDRESS);
    run_op_get_pk_test(myHSM, TZ3, PKH_TEZOS_ADDRESS);
    run_op_get_pk_test(myHSM, TZ3_AUTH, PKH_TEZOS_ADDRESS);

    Serial.println();
    Serial.println("-- Testing Message Signing and Signature Verification (op_sign, 0x21; op_verify, 0x22) --"); Serial.println();
    
    Serial.println(); Serial.println("-- Message Hashed, Signature Raw Bytes --");
    run_op_sign_and_verify_test(myHSM, TZ1, MESSAGE_HASHED_SIG_RAW_BYTES);
    run_op_sign_and_verify_test(myHSM, TZ2, MESSAGE_HASHED_SIG_RAW_BYTES);
    run_op_sign_and_verify_test(myHSM, TZ3, MESSAGE_HASHED_SIG_RAW_BYTES);
    run_op_sign_and_verify_test(myHSM, TZ3_AUTH, MESSAGE_HASHED_SIG_RAW_BYTES);

    Serial.println(); Serial.println("-- Message Hashed, Signature Base58 Checksum Encoded --");
    run_op_sign_and_verify_test(myHSM, TZ1, MESSAGE_HASHED_SIG_BASE58_CHECKSUM_ENCODED);
    run_op_sign_and_verify_test(myHSM, TZ2, MESSAGE_HASHED_SIG_BASE58_CHECKSUM_ENCODED);
    run_op_sign_and_verify_test(myHSM, TZ3, MESSAGE_HASHED_SIG_BASE58_CHECKSUM_ENCODED);
    run_op_sign_and_verify_test(myHSM, TZ3_AUTH, MESSAGE_HASHED_SIG_BASE58_CHECKSUM_ENCODED);

    Serial.println(); Serial.println("-- Message Unhashed, Signature Raw Bytes --");
    run_op_sign_and_verify_test(myHSM, TZ1, MESSAGE_UNHASHED_SIG_RAW_BYTES);
    run_op_sign_and_verify_test(myHSM, TZ2, MESSAGE_UNHASHED_SIG_RAW_BYTES);
    run_op_sign_and_verify_test(myHSM, TZ3, MESSAGE_UNHASHED_SIG_RAW_BYTES);
    run_op_sign_and_verify_test(myHSM, TZ3_AUTH, MESSAGE_UNHASHED_SIG_RAW_BYTES);

    Serial.println(); Serial.println("-- Message Unhashed, Signature Base58 Checksum Encoded --");
    run_op_sign_and_verify_test(myHSM, TZ1, MESSAGE_UNHASHED_SIG_BASE58_CHECKSUM_ENCODED);
    run_op_sign_and_verify_test(myHSM, TZ2, MESSAGE_UNHASHED_SIG_BASE58_CHECKSUM_ENCODED);
    run_op_sign_and_verify_test(myHSM, TZ3, MESSAGE_UNHASHED_SIG_BASE58_CHECKSUM_ENCODED);
    run_op_sign_and_verify_test(myHSM, TZ3_AUTH, MESSAGE_UNHASHED_SIG_BASE58_CHECKSUM_ENCODED);
  }
}
  
void loop() {
	
	if(!debug) {
		
		// TezioHSM_API myHSM(baud, RWKey); 
		
		uint16_t packetLength, replyLength;

		myHSM.wait_for_start_byte();
		// packetLength = myHSM.read_packet();
    myHSM.read_packet();
      	if (myHSM.validate_packet() == 0) {
        	// fail, send error code and proceed after short wait
        	myHSM.send_status_code();
        	delay(1);
      	}
      	else if (myHSM.parse_message() == 0) {
        	// fail, send error code and proceed after short wait
        	myHSM.send_status_code();
        	delay(1);
		}
      	else if (myHSM.execute_op() == 0) {
        	// failed to execute op command
        	myHSM.send_status_code();
        	delay(1);
      	}
      	else {
        	myHSM.send_reply();
      	}
	}
  delay(1); // short wait
}
