/* MIT License

Copyright (c) 2022 Jeffrey R. Groff

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

#define START_BYTE 0x03

#define GET_PK 0x11
#define SIGN 0x21
#define VERIFY 0x22

#define PK_RAW 0
#define PK_COMP 1
#define PK_BASE58 2
#define PK_HASH 3

#define INVALID_PACKET 0xF0
#define PARSE_ERROR 0xF1
#define OP_ERROR 0xF2

typedef struct {
  uint8_t opCode;
  uint8_t param1;
  uint8_t param2;
  uint16_t param3; 
  uint8_t *data;
  uint16_t dataLength;
} tezioPacket;


class TezioWallet_API {
    
    private:
	
		uint16_t api_crc16(uint8_t *data, uint16_t dataLength);
		uint16_t op_get_pk();
		uint16_t op_sign();
		uint16_t op_verify(); 
		uint8_t readWriteKey[32];
		bool debugFlag;
	    
    public:
	
		tezioPacket packet;
		uint8_t buffer[512]; 
	
		TezioWallet_API(uint32_t baud, const uint8_t *RWKey, bool debug = false);
	
		uint16_t reset_packet();
		uint16_t wait_for_start_byte(uint8_t startByte);
		uint16_t read_packet();
		uint16_t validate_packet(uint16_t packetLength);
		uint16_t parse_message(uint16_t packetLength);
		uint16_t execute_op();
		uint16_t send_reply(uint16_t replyLength);
		uint16_t send_error(uint8_t errorCode);

};



#endif