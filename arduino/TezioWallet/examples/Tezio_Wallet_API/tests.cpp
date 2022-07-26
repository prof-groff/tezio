#include <Arduino.h>
#include "TezioWallet_API.h"
#include "tests.h"

char *curveNames[] = {"-- Ed25519 --", "-- Secp256k1 --", "-- NIST P256 --"};

void run_op_get_pk_test(TezioWallet_API myWallet, uint8_t curve, uint8_t mode) {

  /*   curve   ECC curve to use
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
  Serial.println(curveNames[curve - 1]); 
  myWallet.packet.opCode = 0x11; // op_get_pk
  myWallet.packet.param1 = curve;
  myWallet.packet.param2 = mode;
  opResultLength = myWallet.execute_op(); // pk is stored in the buffer
  if (mode == 3 || mode == 4) {
    // print output as char string
    memset(charStrResult, '\0', sizeof(charStrResult));
    memcpy(charStrResult, myWallet.buffer, opResultLength);
    Serial.println(charStrResult);
  }
  else {
    print_hex_data(myWallet.buffer, opResultLength);
  }
  return;
}

void run_op_sign_and_verify_test(TezioWallet_API myWallet, uint8_t curve, uint8_t mode) {

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
    Serial.println(curveNames[curve-1]);

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
    
    myWallet.packet.opCode = 0x21; // op_sign
    myWallet.packet.param1 = curve;
    myWallet.packet.param2 = mode;
    myWallet.packet.dataLength = messageLength;
    myWallet.packet.data = (uint8_t*) malloc(messageLength*sizeof(uint8_t));
    memcpy(myWallet.packet.data, message, messageLength);
    
    // run op
    signatureLength = myWallet.execute_op();
    
    Serial.print("Signature: ");
    if (mode == 1 || mode == 3) { // raw bytes
      memcpy(signature, myWallet.buffer, signatureLength);
      print_hex_data(signature, signatureLength);
    }
    else {
      memcpy(b58signature, myWallet.buffer, signatureLength);
      Serial.println(b58signature);
    }

    Serial.print("Verifying: ");

    myWallet.packet.opCode = 0x22; // op_verify
    myWallet.packet.param1 = curve;
    myWallet.packet.param2 = mode;
    myWallet.packet.param3 = messageLength; // needed if the message is not already hashed.
    myWallet.packet.dataLength = messageLength + signatureLength;
    myWallet.packet.data = (uint8_t*) malloc((messageLength + signatureLength)*sizeof(uint8_t));
    memcpy(myWallet.packet.data, message, messageLength);
    if (mode == 1 || mode == 3) { // raw bytes
      memcpy(&myWallet.packet.data[messageLength], signature, signatureLength);
    }
    else { // base58 checksum encoded signature
      memcpy(&myWallet.packet.data[messageLength], b58signature, signatureLength);
    }

    uint16_t verified = myWallet.execute_op();
    if (verified == 0) {
      Serial.println("Invalid");
    }
    else if (verified == 1) {
      Serial.println("Valid");
    }

    

    
  //  print_hex_data(myWallet.buffer, opResultLength); Serial.println();
  //

  //  char str[] = "5468697320697320616e206578616d706c65206f662061207369676e6564206d6573736167652e";
  //  uint8_t message[(sizeof(str)-1)/2];
  //  hex_chars_to_byte_array(str, sizeof(str), message, sizeof(message));
  //
  //  // Serial.println("Message");
  //  // print_hex_data(message, sizeof(message));
  //
  //  // load data packet
  //  myWallet.packet.opCode = 0x11; // SIGN
  //  myWallet.packet.param1 = 0x01; // curve
  //  myWallet.packet.param2 = 0x01;
  //  myWallet.packet.param3 = 0x0101; // LSB, message not hashed yet, MSB raw sig
  //
  //  myWallet.packet.data = (uint8_t*) malloc(sizeof(message)*sizeof(uint8_t));
  //  memcpy(myWallet.packet.data, message, sizeof(message));
  //
  //  myWallet.packet.dataLength = sizeof(message);
  //  uint16_t signatureLength = myWallet.execute_op();
  //
  //  Serial.println("SIGNATURE RETURNED");
  //  uint8_t signature[64];
  //  memcpy(signature, myWallet.buffer, signatureLength);
  //  print_hex_data(signature, signatureLength);
  //
  //  // signature[10] = 99;
  //
  //  // set up for signature validation
  //  myWallet.packet.opCode = 0x22;
  //  myWallet.packet.data = (uint8_t*) malloc((sizeof(message)+sizeof(signature))*sizeof(uint8_t));
  //  memcpy(myWallet.packet.data, signature, 64);
  //  memcpy(&myWallet.packet.data[64], message, sizeof(message));
  //  // mess with signature
  //  // myWallet.packet.data[10] = 0;
  //  myWallet.packet.dataLength = 64 + sizeof(message);
  //  Serial.println("PACKET DATA");
  //  print_hex_data(myWallet.packet.data, 64+sizeof(message));
  //  uint16_t valid = myWallet.execute_op();
  //  Serial.println(valid);

  

  
}
