#include <TezioHSM_API.h>
#include "api_tests.h"
#include "api_secrets.h" // contains key for encrypted read/write operations

/* 
CURVE/SLOT/KEY ALIASES: 
  TZ3_AUTH (0)
  TZ1 (1)
  TZ2 (2)
  TZ3 (3)

HSM OPERATIONS: 
  OP_GET_PK (0x11)
  OP_SIGN (0x21)
  OP_VERIFY (0x22)

TEZOS OPERATIONS:
  LEGACY_BLOCK (0x01)
  LEGACY_ENDORSEMENT (0x02)
  TRANSFER (0x03)
  AUTHENTICATED_SIGNING_REQUEST (0x04)
  MICHELSON_DATA (0x05)
  BLOCK (0x11)
  PRE_ATTESTATION (0x12)
  ATTESTATION (0x13)
*/

bool debug = false; // true puts device in interactive mode and runs tests using Arduino serial monitor
uint32_t baud = 57600; // if in debug mode, make this 9600
TezioHSM_API myHSM(baud, readWriteKey); 

void setup() {

  if(!debug) {

    myHSM.enable_tezos_op(TZ1, TRANSFER);
    myHSM.enable_tezos_op(TZ2, TRANSFER);
    myHSM.enable_tezos_op(TZ3, TRANSFER);
    myHSM.enable_tezos_op(TZ3_AUTH, TRANSFER);
    
    myHSM.enable_tezos_op(TZ3, BLOCK);
    myHSM.enable_tezos_op(TZ3, PRE_ATTESTATION);
    myHSM.enable_tezos_op(TZ3, ATTESTATION);

    // myHSM.disable_hsm_op(TZ3_AUTH, OP_SIGN);
    // myHSM.disable_hsm_op(TZ1, OP_SIGN);
    // myHSM.disable_hsm_op(TZ2, OP_SIGN);

    myHSM.set_level_hwm(TZ3, BLOCK, 0);
    myHSM.set_level_hwm(TZ3, PRE_ATTESTATION, 0);
    myHSM.set_level_hwm(TZ3, ATTESTATION, 0); 
    
    myHSM.set_round_hwm(TZ3, BLOCK, 0);
    myHSM.set_round_hwm(TZ3, PRE_ATTESTATION, 0);
    myHSM.set_round_hwm(TZ3, ATTESTATION, 0);

  }

  else { // run tests
    Serial.begin(baud);
    delay(1000); // short wait for serial to start up
    set_test_configuration(myHSM); // default is all Tezos and HSM ops are permitted, change in api_tests.cpp
    run_tests(myHSM);
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
