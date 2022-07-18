/*
  The Cryptochip library is remixed from the ArduinoECCX08 library with added functionality.
  
  Copyright (c) 2022 Jeff Groff

  Like the library on which its based, this library is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation; either version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef CRYPTOCHIP_H
#define CRYPTOCHIP_H

#include <Arduino.h>
#include <Wire.h>
#include <sha2.h>

class Cryptochip
{
public:
  Cryptochip(TwoWire& wire, uint8_t address);
  virtual ~Cryptochip();

  int begin();
  void end();

  int serialNumber(byte sn[]);
  String serialNumber();
  
  uint8_t privSessionKey[32]; 

  long random(long max);
  long random(long min, long max);
  int random(byte data[], size_t length);
  
  int info(uint8_t param1, uint16_t param2, uint8_t state[], uint16_t length);

  int generatePrivateKey(int slot, byte publicKey[]);
  int generatePublicKey(int slot, byte publicKey[]);

  int ecdsaVerify(const byte message[], const byte signature[], const byte pubkey[]);
  int ecSign(int slot, const byte message[], byte signature[]);

  int beginSHA256();
  int updateSHA256(const byte data[]); // 64 bytes
  int endSHA256(byte result[]);
  int endSHA256(const byte data[], int length, byte result[]);

  int readSlot(int slot, byte data[], int length);
  int encryptedRead(uint16_t slot, uint8_t cyphertext[], int length);
  int encryptedWrite(uint16_t slot, uint8_t cyphertext[], uint8_t mac[], int length);
  int writeSlot(int slot, const byte data[], int length);
  int privWriteSlot(uint16_t slot, const byte data[], int length);
  int encryptedPrivWrite(uint16_t slot, uint8_t data[], uint16_t length);
  
  void decryptData(uint8_t cyphertext[], uint8_t plaintext[], uint16_t length);
  void encryptData(uint8_t plaintext[], uint8_t cyphertext[], uint16_t length);

  int locked(uint8_t lock_status[]); 
  int writeConfiguration(const byte data[]);
  int readConfiguration(byte data[]);
  
  int lock(); // lock config and data/otp zones
  int lockConfigZone();
  int lockDataOTPZones();
  int lockSlot(int slot);

  int wakeup();
  int sleep();
  int idle();

  long version();
  int challenge(const byte message[]);
  int verify(const byte signature[], const byte pubkey[]);
  int sign(int slot, byte signature[]);

  int read(int zone, int address, byte buffer[], int length);
  int write(int zone, int address, const byte buffer[], int length);
  int lock(int zone);

  int addressForSlotOffset(int slot, int offset);

  int sendCommand(uint8_t opcode, uint8_t param1, uint16_t param2, const byte data[] = NULL, size_t dataLength = 0);
  int receiveResponse(void* response, size_t length);
  uint16_t crc16(const byte data[], size_t length);
  
  int nonce(const uint8_t rand[], uint8_t nonce[], uint8_t rand_length);
  int noncePassThrough(uint8_t nonce[], uint8_t length);
  int genDig(uint16_t keyID, bool noMac = false);
  
  int generateSessionKey(uint16_t keyID, const uint8_t readKey[], uint8_t sessionKey[], bool noMac = false);

private:
  TwoWire* _wire;
  uint8_t _address;

  static const uint32_t _wakeupFrequency;
  static const uint32_t _normalFrequency;
};

// extern Cryptochip ECCX08;

#endif
