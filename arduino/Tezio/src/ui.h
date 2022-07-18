#ifndef UI_H
#define UI_H

#include <Arduino.h>

void start_serial(uint32_t baudRate = 9600); 
void flush_serial();
void print_hex_data(uint8_t data[], uint16_t dataLength);
void print_dec_data(uint8_t data[], uint16_t dataLength);
void wait_forever();
bool confirm_entry();
void confirm_continue();
void get_mnemonic_from_serial(char (*secret_mnemonic)[10]);
void print_mnemonic(char (*secret_mnemonic)[10]);

#endif