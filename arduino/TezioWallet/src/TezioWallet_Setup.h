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

#ifndef TEZIOWALLET_SETUP_H
#define TEZIOWALLET_SETUP_H

#include <Arduino.h>
#include "Cryptochip.h"
#include "ui.h"
#include "bip39.h"
#include "slip10.h"
#include "constants.h"
#include "crypto_helpers.h"
#include <BLAKE2b.h>
#include <uECC.h>

class TezioWallet_Setup {
    
    private:
	
		char mnemonicString[24*10]; 
		uint8_t mnemonicStringLength; 
	
		uint8_t edsk[32];
		uint8_t spsk[32];
		uint8_t p2sk[32];
	
	    
    public:
	
		uint8_t edpk[32];
		uint8_t sppk[64]; // only 33 bytes in compressed format with a prefix 0x02 (y even) or 0x03 (y odd)
		uint8_t p2pk[64];
	
		uint16_t configure(const uint8_t *config_data);
		uint16_t check_mnemonic(char *mnemonic, uint16_t mnemonic_length);
		uint16_t derive_keys(char *path, uint16_t path_length, char* password, uint16_t password_length);
		uint16_t provision(const uint8_t *RWKey);
		
		TezioWallet_Setup();
	
};


#endif