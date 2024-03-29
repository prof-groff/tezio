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

#include "ui.h"

#define MNEMONIC_LENGTH 24

void start_serial(uint32_t baudRate) {
  if(!Serial){
    Serial.begin(baudRate); 
    while(!Serial);
    }
}

void flush_serial() {
  while(Serial.available() > 0) {
    Serial.read();
  }
}

void print_hex_data(uint8_t data[], uint16_t dataLength) {
    for (int i = 0; i < dataLength; i++) {
        Serial.print(data[i], HEX); Serial.print(' ');
      }
      Serial.println();
}

void print_dec_data(uint8_t data[], uint16_t dataLength) {
    for (int i = 0; i < dataLength; i++) {
        Serial.print(data[i], DEC); Serial.print(' ');
      }
      Serial.println();
}

void wait_forever() {
    while(1) {
        delay(100);
    }
}

bool confirm_entry() {
  Serial.println("Confirm (Y/n)");
  char Y[] = "Y";
  char _buffer[2]; memset(_buffer, '\0', 2);
  while(Serial.available()==0);
  Serial.readBytesUntil('\n',_buffer, 2);
  flush_serial();
  if (_buffer[0] == '\0' || strcmp(_buffer,Y) == 0) {
    return true;
  }
  else {
      return false;
  }
}

void confirm_continue() {
	while(1) {
		Serial.println("Ready to continue?");
		if (confirm_entry()) {
			break;
		}
	}
	return;
}


void get_mnemonic_from_serial(char (*secret_mnemonic)[10]) {
    
  char(*p)[10] = secret_mnemonic; // pointer to increment
  start_serial(9600);
  Serial.println("Enter 24-word mnemonic phrase.");
  char mnemonic_word[10];
  uint8_t word_index = 0;
  while (word_index < MNEMONIC_LENGTH) {
    Serial.print("Word "); Serial.print(word_index + 1); Serial.println(':');
    while(Serial.available()==0);
    memset(mnemonic_word, '\0', sizeof(mnemonic_word));
    Serial.readBytesUntil('\n',mnemonic_word,sizeof(mnemonic_word));
    mnemonic_word[sizeof(mnemonic_word)-1] = '\0';
    flush_serial();
    Serial.print("Entered: "); Serial.println(mnemonic_word);
    if (confirm_entry()) {
      // validate_mnemonic_word(mnemonic_word); // NOT YET IMPLEMENTED
      strcpy(*p++, mnemonic_word);
    
      word_index++;
    }
    else {
      Serial.println("Ignoring last entry. Re-enter.");
    }
    
  }
  Serial.println("Mnemonic successfully entered.");
 
}

void print_mnemonic(char (*secret_mnemonic)[10]) {
  for (int i = 0; i < 24; i++) {
    Serial.print(secret_mnemonic[i]); Serial.print(' '); 
  }
  Serial.println();
	return;
}

void send_bytes(uint8_t *data, uint16_t dataLength) {
	Serial.write(data, dataLength);
	return;
}