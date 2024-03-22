#include <Arduino.h>
#include "TezioHSM_API.h"
#include "api_tests.h"

char *curveNames[] = {"-- NIST P256 Authentication Key --", "-- Ed25519 --", "-- Secp256k1 --", "-- NIST P256 --"};

void run_op_get_pk_test(TezioHSM_API myHSM, uint8_t keyAlias, uint8_t mode) {

  /*   curve   ECC curve to use
    0x00    NIST P256 Authentication Key
    0x01    Ed25519
    0x02    Secp256k1
    0x03    NIST P256
  
    mode    pk format
    0x01    raw bytes
    0x02    compressed bytes
    0x03    base58 checksum encoded
    0x04    tezos address hash */

  uint16_t opResultLength;
  char charStrResult[128]; // to hold base58 encoded results for easy printing
  start_serial();
  Serial.println(curveNames[keyAlias]); 
  myHSM.packet.opCode = 0x11; // op_get_pk
  myHSM.packet.param1 = keyAlias;
  myHSM.packet.param2 = mode;
  opResultLength = myHSM.execute_op(); // pk is stored in the buffer
  if (mode == 3 || mode == 4) {
    // print output as char string
    memset(charStrResult, '\0', sizeof(charStrResult));
    memcpy(charStrResult, myHSM.buffer, opResultLength);
    Serial.println(charStrResult);
  }
  else {
    print_hex_data(myHSM.buffer, opResultLength);
  }
  return;
}

void run_op_sign_and_verify_test(TezioHSM_API myHSM, uint8_t keyAlias, uint8_t mode) {

  /*   curve   ECC curve to use
    0x01    Ed25519
    0x02    Secp256k1
    0x03    NIST P256
  
    mode    message is hashed   signature format
    0x01    yes           raw bytes
    0x02    yes           base58 checksum encoded
    0x03    no            raw bytes
    0x04    no            base58 checksum encoded */

    uint8_t message[77];
    uint8_t signature[64];
    char b58signature[100];
    memset(b58signature, '\0', sizeof(b58signature));
    uint16_t messageLength, signatureLength; 

    start_serial(); Serial.println();
    Serial.println(curveNames[keyAlias-1]);

    // generate random bytes for message
    if (mode == 3 || mode == 4) {
      messageLength = 77; // not hashed 
    }
    else {
      messageLength = 32;
    }
    RNG(message, messageLength);
    Serial.print("Message: ");
    print_hex_data(message, messageLength);

    // construct packet
    
    myHSM.packet.opCode = 0x21; // op_sign
    myHSM.packet.param1 = keyAlias;
    myHSM.packet.param2 = mode;
    myHSM.packet.dataLength = messageLength;
    // myHSM.packet.data = (uint8_t*) malloc(messageLength*sizeof(uint8_t));
    memcpy(myHSM.packet.data, message, messageLength);
    
    // run op
    signatureLength = myHSM.execute_op();
    
    Serial.print("Signature: ");
    if (mode == 1 || mode == 3) { // raw bytes
      memcpy(signature, myHSM.buffer, signatureLength);
      print_hex_data(signature, signatureLength);
    }
    else {
      memcpy(b58signature, myHSM.buffer, signatureLength);
      Serial.println(b58signature);
    }

    Serial.print("Verifying: ");

    myHSM.packet.opCode = 0x22; // op_verify
    myHSM.packet.param1 = keyAlias;
    myHSM.packet.param2 = mode;
    myHSM.packet.param3 = messageLength; // needed if the message is not already hashed.
    myHSM.packet.dataLength = messageLength + signatureLength;
    // myHSM.packet.data = (uint8_t*) malloc((messageLength + signatureLength)*sizeof(uint8_t));
    memcpy(myHSM.packet.data, message, messageLength);
    if (mode == 1 || mode == 3) { // raw bytes
      memcpy(&myHSM.packet.data[messageLength], signature, signatureLength);
    }
    else { // base58 checksum encoded signature
      memcpy(&myHSM.packet.data[messageLength], b58signature, signatureLength);
    }

    uint16_t verified = myHSM.execute_op();
    if (verified == 0) {
      Serial.println("Invalid");
    }
    else if (verified == 1) {
      Serial.println("Valid");
    }
  
}
