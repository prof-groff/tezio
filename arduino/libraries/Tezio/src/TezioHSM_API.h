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

#ifndef TEZIOHSM_API_H
#define TEZIOHSM_API_H

#include <Arduino.h>
#include "ui.h"
#include "constants.h"
#include "crypto_helpers.h"
#include "Cryptochip.h"
// #include "TezioHSM_Config.h"

#define N_KEYS 4 // NISTP256_AUTH, Secp256k1, Ed25519, NISTP256
#define MAX_DATA_LENGTH 1024

// PARAMETERS FOR ALLOCATING MEMORY
#define N_TEZOS_OPS 0x13 // this uses more space then needed but is convenient
#define N_HSM_OPS 0x22 // same
#define N_BAKING_OPERATIONS 3 // when baking op prefix bytes are used to access, need to subtract 0x11

#define START_BYTE 0x03
#define N_RETRIES 100

#define GET_PK 0x11
#define SIGN 0x21
#define VERIFY 0x22

#define PK_RAW 0
#define PK_COMP 1
#define PK_BASE58 2
#define PK_HASH 3

// prefix lengths
#define P2_SIG_PREFIX_LENGTH 4
#define SP_SIG_PREFIX_LENGTH 5
#define ED_SIG_PREFIX_LENGTH 5

// PASS or FAIL
#define FAIL 0x00
#define FORBIDDEN 0x00
#define PASS 0x01
#define SUCCESS 0x01
#define ALLOWED 0x01

// STATUS CODES
#define START_BYTE_FOUND 0xD1
#define PACKET_OF_EXPECTED_LENGTH_ARRIVED 0xD2
#define VALID_PACKET_RECEIVED 0xD3
#define PACKET_PARSED_SUCCESSFULLY 0xD4

// ERRORS STATUS CODES
#define PARAM_1_INVALID 0xAA
#define PARAM_2_INVALID 0xAB
#define PARAM_3_INVALID 0xAC
#define DATA_OR_DATA_LENGTH_INVALID 0xAD
#define MESSAGE_HASH_STATUS_INDETERMINANT 0xAE
#define HSM_FAILED_TO_SIGN 0xAF
#define HSM_OPERATION_FORBIDDEN_BY_POLICY 0xB0
#define FAILED_TO_GENERATE_SESSION_KEY 0xB1
#define ENCRYPTED_READ_FAILED 0xB2
#define FAILED_TO_DECRYPT_DATA 0xB3
#define FAILED_TO_READ_PK_SLOT 0xB4
#define FAILED_TO_ENCRYPT_DATA 0xB5
#define FAILED_ENCRYPTED_WRITE 0xB6
#define FAILED_CLEAR_WRITE 0xB7
#define SIGNING_OPERATION_FORBIDDEN_BY_POLICY 0xB8

#define INVALID_KEY_ALIAS 0xA0
#define CRYPTOCHIP_FAILED_TO_INITIALIZE 0xA1
#define INVALID_OPERATION_CODE 0xA2
#define LEVEL_ROUND_HIGHWATERMARK_ERROR 0xA3
#define LENGTH_BYTES_FAILED_TO_ARRIVE 0xA4
#define UNEXPECTED_PACKET_LENGTH 0xA5
#define INSUFFICIENT_PACKET_LENGTH 0xA6
#define INVALID_CRC16 0xA7
#define INVALID_PACKET_LENGTH 0xA8
#define FAILED_TO_RESET_PACKET 0xA9


// operation execution errors

#define PARSE_ERROR 0xF1
#define OP_ERROR 0xF2

// signing errors

#define FORBIDDEN_BY_SIGNING_POLICY 0xE0
#define FORBIDDEN_BY_HIGH_WATERMARKS 0xE1
#define AUTHENTICATION_REQUIRED 0xE2

typedef struct {
  uint8_t opCode;
  uint8_t param1;
  uint8_t param2;
  uint16_t param3; 
  uint8_t data[MAX_DATA_LENGTH];
  uint16_t dataLength;
  uint16_t packetLength;
} tezioPacket;

typedef struct {
    uint32_t level[N_BAKING_OPERATIONS] = {0};
    uint32_t round[N_BAKING_OPERATIONS] = {0};
} hwmStruct; 

typedef struct {
    uint8_t tezos_ops[N_TEZOS_OPS] = {0}; // no ops allowed by default
	uint8_t hsm_ops[N_HSM_OPS] = {0}; // no ops allowed by default
} policyStruct;

class TezioHSM_API {
    
    private:
	
		uint16_t api_crc16(uint8_t *data, uint16_t dataLength);
		uint16_t op_get_pk();
		uint16_t op_sign();
		uint16_t op_verify(); 
		
		uint8_t readWriteKey[32];
		uint32_t myBaud;

		uint16_t validate_level_round();
		uint16_t validate_param_1_2(uint8_t param, uint8_t minVal, uint8_t maxVal);
		uint16_t validate_param_3(uint16_t param, uint16_t minVal, uint16_t maxVal);
		uint16_t validate_data(uint8_t *data, uint16_t dataLength, uint16_t minLength, uint16_t maxLength);
		uint16_t reset_packet();
		
    public:
	
		tezioPacket packet;
		uint16_t packetLength;
		hwmStruct hwm[N_KEYS]; // space for all curves and all operations
		policyStruct policy[N_KEYS]; 
		uint8_t buffer[1024]; 
		uint16_t bufferLength; // number of bytes currently sitting in the buffer
		uint16_t errorCode;
		uint16_t statusCode;
	
		TezioHSM_API(uint32_t baud, const uint8_t *RWKey);
		~TezioHSM_API();
	
		uint16_t wait_for_start_byte();
		uint16_t read_packet();
		uint16_t validate_packet();
		uint16_t parse_message();
		uint16_t execute_op();
		uint16_t send_reply();
		uint16_t send_status_code();

		void enable_tezos_op(uint8_t key_alias, uint8_t op);
		void disable_hsm_op(uint8_t key_alias, uint8_t op);

		void set_level_hwm(uint8_t key_alias, uint8_t baking_op, uint32_t hwmValue);
		void set_round_hwm(uint8_t key_alias, uint8_t baking_op, uint32_t hwmValue);

};



#endif