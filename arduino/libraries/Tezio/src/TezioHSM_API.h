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

// PARAMETERS FOR ALLOCATING MEMORY
#define N_OPERATIONS 0x13 // this uses more space then needed but is convenient
#define N_BAKING_OPERATIONS 3 // if indeces are used to access, need to subtract 0x11

#define START_BYTE 0x03
#define N_RETRIES 100

#define GET_PK 0x11
#define SIGN 0x21
#define VERIFY 0x22
#define CLEAR_WRITE 0x31
#define WRITE_KEYS 0x32

#define PK_RAW 0
#define PK_COMP 1
#define PK_BASE58 2
#define PK_HASH 3

// PASS or FAIL
#define FAIL 0x00
#define PASS 0x01

// STATUS CODES
#define START_BYTE_FOUND 0xB1
#define PACKET_OF_EXPECTED_LENGTH_ARRIVED 0xB2
#define VALID_PACKET_RECEIVED 0xB3
#define PACKET_PARSED_SUCCESSFULLY 0xB4

// ERRORS STATUS CODES
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
  uint8_t data[1024];
  uint16_t dataLength;
  uint16_t packetLength;
} tezioPacket;

typedef struct {
    uint32_t level[N_BAKING_OPERATIONS] = {0};
    uint32_t round[N_BAKING_OPERATIONS] = {0};
} hwmStruct; 

typedef struct {
    uint8_t operation[N_OPERATIONS] = {0};
} policyStruct;

// void set_signing_policies(policyStruct *policy);
// void set_high_water_marks(hwmStruct *hwm);

class TezioHSM_API {
    
    private:
	
		uint16_t api_crc16(uint8_t *data, uint16_t dataLength);
		uint16_t op_get_pk();
		uint16_t op_sign();
		uint16_t op_verify(); 
		uint16_t op_clear_write();
		uint16_t op_write_keys(); // encrypted write secret key, clear write public key
		
		uint8_t readWriteKey[32];
		uint32_t myBaud;

		uint16_t validate_level_round();
		uint16_t check_key_alias();
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

		void enable_signing(uint8_t key_alias, uint8_t op);
		void disable_signing(uint8_t key_alias, uint8_t op);

		void set_level_hwm(uint8_t key_alias, uint8_t baking_op, uint32_t hwmValue);
		void set_round_hwm(uint8_t key_alias, uint8_t baking_op, uint32_t hwmValue);

};



#endif