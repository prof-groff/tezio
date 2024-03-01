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

#ifndef TEZIOWALLET_API_H
#define TEZIOWALLET_API_H

#include <Arduino.h>
#include "ui.h"
#include "constants.h"
#include "crypto_helpers.h"
#include "Cryptochip.h"
#include "Tezio_Config.h"

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
#define INVALID 0x00
#define VALID 0x01
#define INVALID_PACKET 0x00
#define VALID_PACKET 0x01
#define NOT_FOUND 0x00
#define FOUND 0x01
#define UNFINISHED 0x00
#define FINISHED 0x01

// STATUS CODES
#define START_BYTE_FOUND 0xB1
#define PACKET_OF_EXPECTED_LENGTH_ARRIVED 0xB2
#define VALID_PACKET_RECEIVED 0xB3

// ERRORS STATUS CODES
#define INVALID_CURVE_ALIAS 0xA0
#define CRYPTOCHIP_FAILED_TO_INITIALIZE 0xA1
#define INVALID_OPERATION_CODE 0xA2
#define LEVEL_ROUND_HIGHWATERMARK_ERROR 0xA3
#define LENGTH_BYTES_FAILED_TO_ARRIVE 0xA4
#define UNEXPECTED_PACKET_LENGTH 0xA5
#define INSUFFICIENT_PACKET_LENGTH 0xA6
#define INVALID_CRC16 0xA7
#define INVALID_PACKET_LENGTH 0xA8


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



class TezioHSM_API {
    
    private:
	
		uint16_t api_crc16(uint8_t *data, uint16_t dataLength);
		uint16_t op_get_pk();
		uint16_t op_sign();
		uint16_t op_verify(); 
		uint16_t op_clear_write();
		uint16_t op_write_keys(); // encrypted write secret key, clear write public key
		
		uint16_t auth_sig_verify(uint8_t *messageBytes, uint16_t messageLength, uint8_t *signatureBytes);
		uint8_t readWriteKey[32];
		uint8_t authenticationPkh[PKH_SIZE]; // need to initialize
		uint8_t authenticationPk[P2_PK_SIZE]; // need to initialize
		uint32_t myBaud;

		uint16_t validate_level_round();
		uint16_t check_curve_alias();
		
	    
    public:
	
		tezioPacket packet;
		hwmStruct hwm[N_CURVES]; // space for all curves and all operations
		policyStruct policy[N_CURVES]; 
		uint8_t buffer[1024]; 
		uint16_t bufferLength; // number of bytes currently sitting in the buffer
		uint16_t errorCode;
		uint16_t statusCode;
	
		TezioHSM_API(uint32_t baud, const uint8_t *RWKey);
		~TezioHSM_API();
	
		uint16_t reset_packet();
		uint16_t wait_for_start_byte();
		uint16_t read_packet();
		uint16_t validate_packet();
		uint16_t parse_message();
		uint16_t execute_op();
		uint16_t send_reply(uint16_t replyLength);
		uint16_t send_error(uint8_t errorCode);

};



#endif