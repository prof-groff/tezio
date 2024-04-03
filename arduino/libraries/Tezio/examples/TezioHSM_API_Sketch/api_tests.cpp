#include <Arduino.h>
#include "TezioHSM_API.h"
#include "api_tests.h"

char *curveNames[] = {"-- NIST P256 Authentication Key --", "-- Ed25519 --", "-- Secp256k1 --", "-- NIST P256 --"};
uint8_t prefixBytes[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x11, 0x12, 0x13}; 

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
  myHSM.packet.opCode = OP_GET_PK; // op_get_pk
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
  0x00    NIST P256 Auth
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

  message[0] = 0x03; // prefix byte 

  Serial.print("Message: ");
  print_hex_data(message, messageLength);

  // construct packet
    
  myHSM.packet.opCode = OP_SIGN; // op_sign
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

  myHSM.packet.opCode = OP_VERIFY; // op_verify
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

void set_test_configuration(TezioHSM_API myHSM) {

  myHSM.enable_tezos_op(TZ3_AUTH, LEGACY_BLOCK);
  myHSM.enable_tezos_op(TZ3_AUTH, LEGACY_ENDORSEMENT);
  myHSM.enable_tezos_op(TZ3_AUTH, TRANSFER);
  myHSM.enable_tezos_op(TZ3_AUTH, AUTHENTICATED_SIGNING_REQUEST);
  myHSM.enable_tezos_op(TZ3_AUTH, MICHELSON_DATA);
  myHSM.enable_tezos_op(TZ3_AUTH, BLOCK);
  myHSM.enable_tezos_op(TZ3_AUTH, PRE_ATTESTATION);
  myHSM.enable_tezos_op(TZ3_AUTH, ATTESTATION);

  myHSM.enable_tezos_op(TZ1, LEGACY_BLOCK);
  myHSM.enable_tezos_op(TZ1, LEGACY_ENDORSEMENT);
  myHSM.enable_tezos_op(TZ1, TRANSFER);
  myHSM.enable_tezos_op(TZ1, AUTHENTICATED_SIGNING_REQUEST);
  myHSM.enable_tezos_op(TZ1, MICHELSON_DATA);
  myHSM.enable_tezos_op(TZ1, BLOCK);
  myHSM.enable_tezos_op(TZ1, PRE_ATTESTATION);
  myHSM.enable_tezos_op(TZ1, ATTESTATION);

  myHSM.enable_tezos_op(TZ2, LEGACY_BLOCK);
  myHSM.enable_tezos_op(TZ2, LEGACY_ENDORSEMENT);
  myHSM.enable_tezos_op(TZ2, TRANSFER);
  myHSM.enable_tezos_op(TZ2, AUTHENTICATED_SIGNING_REQUEST);
  myHSM.enable_tezos_op(TZ2, MICHELSON_DATA);
  myHSM.enable_tezos_op(TZ2, BLOCK);
  myHSM.enable_tezos_op(TZ2, PRE_ATTESTATION);
  myHSM.enable_tezos_op(TZ2, ATTESTATION);

  myHSM.enable_tezos_op(TZ3, LEGACY_BLOCK);
  myHSM.enable_tezos_op(TZ3, LEGACY_ENDORSEMENT);
  myHSM.enable_tezos_op(TZ3, TRANSFER);
  myHSM.enable_tezos_op(TZ3, AUTHENTICATED_SIGNING_REQUEST);
  myHSM.enable_tezos_op(TZ3, MICHELSON_DATA);
  myHSM.enable_tezos_op(TZ3, BLOCK);
  myHSM.enable_tezos_op(TZ3, PRE_ATTESTATION);
  myHSM.enable_tezos_op(TZ3, ATTESTATION);

  // myHSM.disable_hsm_op(TZ3_AUTH, OP_GET_PK);
  // myHSM.disable_hsm_op(TZ1, OP_GET_PK);
  // myHSM.disable_hsm_op(TZ2, OP_GET_PK);
  // myHSM.disable_hsm_op(TZ3, OP_GET_PK);

  // myHSM.disable_hsm_op(TZ3_AUTH, OP_SIGN);
  // myHSM.disable_hsm_op(TZ1, OP_SIGN);
  // myHSM.disable_hsm_op(TZ2, OP_SIGN);
  // myHSM.disable_hsm_op(TZ3, OP_SIGN);

  // myHSM.disable_hsm_op(TZ3_AUTH, OP_VERIFY);
  // myHSM.disable_hsm_op(TZ1, OP_VERIFY);
  // myHSM.disable_hsm_op(TZ2, OP_VERIFY);
  // myHSM.disable_hsm_op(TZ3, OP_VERIFY);

  myHSM.set_level_hwm(TZ3, BLOCK, 0);
  myHSM.set_level_hwm(TZ3, PRE_ATTESTATION, 0);
  myHSM.set_level_hwm(TZ3, ATTESTATION, 0); 
    
  myHSM.set_round_hwm(TZ3, BLOCK, 0);
  myHSM.set_round_hwm(TZ3, PRE_ATTESTATION, 0);
  myHSM.set_round_hwm(TZ3, ATTESTATION, 0);

}


void run_tests(TezioHSM_API myHSM) {
  
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

