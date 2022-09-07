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

#include "Cryptochip.h"

const uint32_t Cryptochip::_wakeupFrequency = 100000u;  // 100 kHz
#ifdef __AVR__
const uint32_t Cryptochip::_normalFrequency = 400000u;  // 400 kHz
#else
const uint32_t Cryptochip::_normalFrequency = 1000000u; // 1 MHz
#endif

Cryptochip::Cryptochip(TwoWire& wire, uint8_t address) :
  _wire(&wire),
  _address(address)
{
}

Cryptochip::~Cryptochip()
{
}

int Cryptochip::begin()
{
  _wire->begin();

  wakeup();
  idle();
  
  long ver = version() & 0x0F00000;

  if (ver != 0x0500000 && ver != 0x0600000) {
    return 0;
  }

  return 1;
}

void Cryptochip::end()
{
  // First wake up the device otherwise the chip didn't react to a sleep commando
  wakeup();
  sleep();
#ifdef WIRE_HAS_END
  _wire->end();
#endif
}

int Cryptochip::serialNumber(byte sn[])
{
  if (!read(0, 0, &sn[0], 4)) {
    return 0;
  }

  if (!read(0, 2, &sn[4], 4)) {
    return 0;
  }

  if (!read(0, 3, &sn[8], 4)) {
    return 0;
  }

  return 1;
}

String Cryptochip::serialNumber()
{
  String result = (char*)NULL;
  byte sn[12];

  if (!serialNumber(sn)) {
    return result;
  }

  result.reserve(18);

  for (int i = 0; i < 9; i++) {
    byte b = sn[i];

    if (b < 16) {
      result += "0";
    }
    result += String(b, HEX);
  }

  result.toUpperCase();

  return result;
}

long Cryptochip::random(long max)
{
  return random(0, max);
}

long Cryptochip::random(long min, long max)
{
  if (min >= max)
  {
    return min;
  }

  long diff = max - min;

  long r;
  random((byte*)&r, sizeof(r));

  if (r < 0) {
    r = -r;
  }

  r = (r % diff);

  return (r + min);
}

int Cryptochip::random(byte data[], size_t length)
{
  if (!wakeup()) {
    return 0;
  }

  while (length) {
    if (!sendCommand(0x1b, 0x00, 0x0000)) {
      return 0;
    }

    delay(23);

    byte response[32];

    if (!receiveResponse(response, sizeof(response))) {
      return 0;
    }

    int copyLength = min(32, (int)length);
    memcpy(data, response, copyLength);

    length -= copyLength;
    data += copyLength;
  }

  delay(1);

  idle();

  return 1;
}

int Cryptochip::info(uint8_t param1, uint16_t param2, uint8_t state[], uint16_t length) {
    // returns information about the tempkey but could be configured via param1 to work in other ways
    if (!wakeup()) {
        return 0;
    }
    
    uint8_t opcode = 0x30;
    
    if (!sendCommand(opcode, param1, param2)){
        return 0;
    }
    
    delay(10);
    
    if (!receiveResponse(state, length)) {
        return 0;
    }
    
    delay(1);

    idle();
        
    return 1;
    
}


int Cryptochip::nonce(const uint8_t rand[], uint8_t nonce[], uint8_t rand_length) {
    
    if (!wakeup()) {
        return 0;
    }
    
    uint8_t opcode = 0x16;
    uint8_t param1 = 0x00;
    uint16_t param2 = 0x0000;
    
    if (!sendCommand(opcode, param1, param2, rand, rand_length)) {
        return 0;
    }
    
    delay(20);
    
    if (!receiveResponse(nonce, rand_length)) {
        return 0;
    }
    
    delay(1);

    idle();
        
    return 1;
    
}

int Cryptochip::noncePassThrough(uint8_t nonce[], uint8_t length) {
    
    // store a nonce in tempkey
    uint8_t status;
    
    if (!wakeup()) {
        return 0;
    }
    
    uint8_t opcode = 0x16;
    uint8_t param1 = 0x03;
    uint16_t param2 = 0x0000;
    
    if (!sendCommand(opcode, param1, param2, nonce, length)) {
        return 0;
    }
    
    delay(20);
    
    if (!receiveResponse(&status, 1)) {
        return 0;
    }
    
    delay(1);

    idle();
    
    if (status != 0) {
        return 0;
    }
        
    return 1;
    
}

int Cryptochip::genDig(uint16_t keyID, bool noMac) {
    if (!wakeup()) {
        return 0;
    }
    
    uint8_t opcode = 0x15;
    uint8_t param1 = 0x02;
    
    if (noMac) {
        uint8_t otherdata[4] = {0, 0, 0, 0};

    
        if (!sendCommand(opcode, param1, keyID, otherdata, sizeof(otherdata))) {
        return 0;
    }
    
    }
    else {
        if (!sendCommand(opcode, param1, keyID)){
            return 0;
        }
    }
    
    delay(20);
    
    uint8_t _status;
    if (!receiveResponse(&_status, sizeof(_status))) {
        return 0;
    }
    
    if(_status != 0) {
        Serial.println(_status);
    }
    
    delay(1);

    idle();
        
    return 1;
}

int Cryptochip::generateSessionKey(uint16_t keyID, const uint8_t RWKey[], uint8_t sessionKey[], bool noMac) {
  // retrieve serial number
	
	
  uint8_t sn[12];
  if (!serialNumber(sn)) {
    return 0;
  }
  // generate 20 byte random number to be rand_in for nonce command. this is done on the ateccx08 instead of the system because
  // this step seems to be necessary to initialize the RNG for subsequent steps too
  uint8_t rand_in[20];
  if (!random(rand_in, 20)) {
    return 0;
  }
	
	
  // execute nonce command and return rand_out
  uint8_t rand_out[32];
  if (!nonce(rand_in, rand_out, 32)) {
    return 0;
  }
  // do SHA256 to calculate the value stored in tempKey after the nonce command
  // message to SHA256 hash = rand_out | rand_in | nonce opcode | mode | 0x00
  uint8_t _buffer[96]; // buffer to hold message
  uint16_t mlength = sizeof(rand_out) + sizeof(rand_in) + 1 + 1 + 1;
  memcpy(&_buffer[0], &rand_out[0], 32);
  memcpy(&_buffer[32], &rand_in[0], 20);
  _buffer[52] = 0x16;
  _buffer[53] = 0x00;
  _buffer[54] = 0x00;
  uint8_t nonce[32];
  sha256_func_host(_buffer, mlength, nonce);

	

  // execute gendig command
  if (!genDig(keyID, noMac)) {
    return 0;
  }

  // do SHA256 again to calculate session key resulting from gendig command
  memset(&_buffer[0], 0, sizeof(_buffer)); // clear buffer out of good measure, probably not needed
  mlength = 96;
  // if noMac is true, message = READ_KEY | other data (4 bytes) | SN[8] | SN[0:1] | ZEROS[25] | nonce
  // if noMac is false, message = READ_KEY | genDig Opcode | Zone | ReadKeyID | SN[8] | SN[0:1] | ZEROS[25] | nonce
  memcpy(&_buffer[0], &RWKey[0], 32);
  if (noMac) { // the slotConfig.noMac bit is set to one which changes the sha256 message
    uint8_t otherdata[4] = {0, 0, 0, 0};
    memcpy(&_buffer[32], &otherdata[0], 4);
  }
  else {
    _buffer[32] = 0x15; // op code
    _buffer[33] = 0x02; // zone
    _buffer[34] = (uint8_t)(keyID); // lsb of keyID
    _buffer[35] = (uint8_t)(keyID >> 8); // msb of keyID
  }
  _buffer[36] = sn[8];
  _buffer[37] = sn[0];
  _buffer[38] = sn[1];
  uint8_t zeros[25];
  memset(zeros, 0, 25);
  memcpy(&_buffer[39], &zeros[0], 25);
  memcpy(&_buffer[64], &nonce[0], 32);

  // calculate session key stored in tempKey
  sha256_func_host(_buffer, mlength, sessionKey);
    
  memcpy(&privSessionKey[0], &sessionKey[0], 32);

  return 1;
}

int Cryptochip::generatePrivateKey(int slot, byte publicKey[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x40, 0x04, slot)) {
    return 0;
  }

  delay(115);

  if (!receiveResponse(publicKey, 64)) {
    return 0;
  }

  delay(1);

  idle();

  return 1;
}

int Cryptochip::generatePublicKey(int slot, byte publicKey[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x40, 0x00, slot)) {
    return -1;
  }

  delay(115);

  if (!receiveResponse(publicKey, 64)) {
    return -2;
  }

  delay(1);

  idle();

  return 1;
}

int Cryptochip::ecdsaVerify(const byte message[], const byte signature[], const byte pubkey[])
{
  if (!challenge(message)) {
    return 0;
  }

  if (!verify(signature, pubkey)) {
    return 0;
  }

  return 1;
}

int Cryptochip::ecSign(int slot, const byte message[], byte signature[])
{
  byte rand[32];

  if (!random(rand, sizeof(rand))) {
    return 0;
  }

  if (!challenge(message)) {
    return 0;
  }

  if (!sign(slot, signature)) {
    return 0;
  }

  return 1;
}

int Cryptochip::beginSHA256()
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x47, 0x00, 0x0000)) {
    return 0;
  }

  delay(9);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

 if (status != 0) {
    return 0;
  } 

  return 1;
}

int Cryptochip::updateSHA256(const byte data[])
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x47, 0x01, 64, data, 64)) {
    return 0;
  }

  delay(9);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int Cryptochip::endSHA256(byte result[])
{
  return endSHA256(NULL, 0, result);
}

int Cryptochip::endSHA256(const byte data[], int length, byte result[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x47, 0x02, length, data, length)) {
    return 0;
  }

  delay(9);

  if (!receiveResponse(result, 32)) {
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

int Cryptochip::readSlot(int slot, byte data[], int length)
{
  if (slot < 0 || slot > 15) {
    return -1;
  }

  if (length % 4 != 0) {
    return 0;
  }

  int chunkSize = 32;

  for (int i = 0; i < length; i += chunkSize) {
    if ((length - i) < 32) {
      chunkSize = 4;
    }

    if (!read(2, addressForSlotOffset(slot, i), &data[i], chunkSize)) {
      return 0;
    }
  }

  return 1;
}

int Cryptochip::writeSlot(int slot, const byte data[], int length)
{
  if (slot < 0 || slot > 15) {
    return -1;
  }

  if (length % 4 != 0) {
    return 0;
  }

  int chunkSize = 32;

  for (int i = 0; i < length; i += chunkSize) {
    if ((length - i) < 32) {
      chunkSize = 4;
    }

    if (!write(2, addressForSlotOffset(slot, i), &data[i], chunkSize)) {
      return 0;
    }
  }

  return 1;
}

int Cryptochip::privWriteSlot(uint16_t slot, const byte data[], int length) {
    uint8_t status;
    if (slot < 0 || slot > 15) {
        return 0;
    }
    if (length != 36) {
        return 0;
    }
    
    if (!wakeup()) {
        return 0;
    }
    

    if (!sendCommand(0x46, 0x00, slot, data, length)) {
        return 0;
    }

    delay(70);

    if (!receiveResponse(&status, sizeof(status))) {
        return 0;
    }

    delay(1);
    idle();
    
    if(status != 0) {
        Serial.println(status, HEX);
        return 0;
    }
    
    
    return 1;
    
}

int Cryptochip::encryptedPrivWrite(uint16_t slot, uint8_t data[], uint16_t length) {
    
    uint8_t status;
    
    uint8_t opcode = 0x46;
    uint8_t param1 = 0x40; 
    
    
    if (!wakeup()) {
        return 0;
    }
    

    if (!sendCommand(opcode, param1, slot, data, length)) {
        return 0;
    }

    delay(50);

    if (!receiveResponse(&status, sizeof(status))) {
        Serial.println("Error receiving.");
        return 0;
    }

    delay(1);
    idle();
    
    if(status != 0) {
        Serial.print("Status: ");
        Serial.println(status, HEX);
        return 0;
    }
    
    
    return 1;
    
    
}

int Cryptochip::locked(uint8_t lock_status[])
{
  byte config[4];

  if (!read(0, 0x15, config, sizeof(config))) {
    return 0;
  }
    
  if (config[2] == 0x55) { // Data/OTP zone is unlocked
      lock_status[0] = 0;
  }
    else {
        lock_status[0] = 1;
    }
    
  if (config[3] == 0x55) { // Configuration zone is unlocked
    lock_status[1] = 0;
  }
    else {
        lock_status[1] = 1;
    }
    
  return 1;
}

int Cryptochip::writeConfiguration(const byte data[])
{
  // skip first 16 bytes, they are not writable
  for (int i = 16; i < 128; i += 4) {
    if (i == 84) {
      // not writable
      continue;
    }

    if (!write(0, i / 4, &data[i], 4)) {
      return 0;
    }
  }

  return 1;
}

int Cryptochip::readConfiguration(byte data[])
{
  for (int i = 0; i < 128; i += 32) {
    if (!read(0, i / 4, &data[i], 32)) {
      return 0;
    }
  }

  return 1;
}

int Cryptochip::lock()
{
  // lock config
  if (!lock(0)) {
    return 0;
  }

  // lock data and OTP
  if (!lock(1)) {
    return 0;
  }

  return 1;
}

int Cryptochip::lockConfigZone() {
    if (!lock(0)) {
        return 0;
    }
    return 1;
}

int Cryptochip::lockDataOTPZones() {
    if (!lock(1)) {
        return 0;
    }
    return 1;
}

int Cryptochip::lockSlot(int slot) {
    if (!lock((slot << 2) | 2)) {
        return 0;
    }
    return 1;
}

int Cryptochip::wakeup()
{
  _wire->setClock(_wakeupFrequency);
  _wire->beginTransmission(0x00);
  _wire->endTransmission(); 

  delayMicroseconds(1500);

  byte response;

  if (!receiveResponse(&response, sizeof(response)) || response != 0x11) {
    return 0;
  }

  _wire->setClock(_normalFrequency);

  return 1;
}

int Cryptochip::sleep()
{
  _wire->beginTransmission(_address);
  _wire->write(0x01);

  if (_wire->endTransmission() != 0) {
    return 0;
  }

  delay(1);

  return 1;
}

int Cryptochip::idle()
{
  _wire->beginTransmission(_address);
  _wire->write(0x02);

  if (_wire->endTransmission() != 0) {
    return 0;
  }

  delay(1);

  return 1;
}

long Cryptochip::version()
{
  uint32_t version = 0;

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x30, 0x00, 0x0000)) {
    return 0;
  }

  delay(2);

  if (!receiveResponse(&version, sizeof(version))) {
    return 0;
  }

  delay(1);
  idle();

  return version;
}

int Cryptochip::challenge(const byte message[])
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  // Nounce, pass through
  if (!sendCommand(0x16, 0x03, 0x0000, message, 32)) {
    return 0;
  }

  delay(29);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int Cryptochip::verify(const byte signature[], const byte pubkey[])
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  byte data[128];
  memcpy(&data[0], signature, 64);
  memcpy(&data[64], pubkey, 64);

  // Verify, external, P256
  if (!sendCommand(0x45, 0x02, 0x0004, data, sizeof(data))) {
    return 0;
  }

  delay(72);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int Cryptochip::sign(int slot, byte signature[])
{
  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x41, 0x80, slot)) {
    return 0;
  }

  delay(70);

  if (!receiveResponse(signature, 64)) {
    return 0;
  }

  delay(1);
  idle();

  return 1;
}

int Cryptochip::read(int zone, int address, byte buffer[], int length)
{
  if (!wakeup()) {
    return 0;
  }

  if (length != 4 && length != 32) {
    return 0;
  }

  if (length == 32) {
    zone |= 0x80;
  }

  if (!sendCommand(0x02, zone, address)) {
    return 0;
  }

  delay(5);

  if (!receiveResponse(buffer, length)) {
    return 0;
  }

  delay(1);
  idle();

  return length;
}

int Cryptochip::encryptedRead(uint16_t slot, uint8_t cyphertext[], int length) {
    uint8_t opcode = 0x02;
    uint8_t param1 = 0x82;
    uint16_t address = addressForSlotOffset(slot, 0);
    
    if (!wakeup()) {
    return 0;
  }


  if (!sendCommand(opcode, param1, address)) {
    return 0;
  }

  delay(20);
    

  if (!receiveResponse(cyphertext, length)) {
    return 0;
  }

  delay(1);
  idle();
    
    return 1;
}


int Cryptochip::encryptedWrite(uint16_t slot, uint8_t cyphertext[], uint8_t mac[], int length) {
    uint8_t opcode = 0x12;
    uint8_t param1 = 0x82; // 0x82
    uint16_t address = addressForSlotOffset(slot, 0);
    
    if (!wakeup()) {
    return 0;
  }
  
 uint16_t datalength = length + length;
 uint8_t data[datalength]; 
 memcpy(&data[0], &cyphertext[0], length);
 memcpy(&data[32], &mac[0], length);
    Serial.println("data to be sent to command, cyphertext + mac");
for (int i = 0; i < datalength; i++) {
    Serial.print(data[i], HEX); Serial.print(' ');
}
    Serial.println();
    Serial.println();
    
Serial.println("Datalength");
    Serial.println(datalength);
    
  // uint8_t test_data[datalength-1];
  // memcpy(&test_data[0], &data[0], sizeof(test_data));

  if (!sendCommand(opcode, param1, address, data, sizeof(data))) {
    return 0;
  }

  delay(100);
    
  uint8_t _status;
  if (!receiveResponse(&_status, 1)) {
    return 0;
  }
    
  if (_status !=0) {
      Serial.println(_status, HEX);
      return 0;
      
  }

  delay(1);
  idle();
    
    return 1;
}


int Cryptochip::write(int zone, int address, const byte buffer[], int length)
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  if (length != 4 && length != 32) {
    return 0;
  }

  if (length == 32) {
    zone |= 0x80;
  }

  if (!sendCommand(0x12, zone, address, buffer, length)) {
    return 0;
  }

  delay(26);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}

int Cryptochip::lock(int zone)
{
  uint8_t status;

  if (!wakeup()) {
    return 0;
  }

  if (!sendCommand(0x17, 0x80 | zone, 0x0000)) {
    return 0;
  }

  delay(32);

  if (!receiveResponse(&status, sizeof(status))) {
    return 0;
  }

  delay(1);
  idle();

  if (status != 0) {
    return 0;
  }

  return 1;
}


int Cryptochip::addressForSlotOffset(int slot, int offset)
{
  int block = offset / 32;
  offset = (offset % 32) / 4;  

  return (slot << 3) | (block << 8) | (offset);
}

int Cryptochip::sendCommand(uint8_t opcode, uint8_t param1, uint16_t param2, const byte data[], size_t dataLength)
{
  int commandLength = 8 + dataLength; // 1 for type, 1 for length, 1 for opcode, 1 for param1, 2 for param2, 2 for crc
  byte command[commandLength]; 
    
  command[0] = 0x03;
  command[1] = sizeof(command) - 1;
  command[2] = opcode;
  command[3] = param1;
  memcpy(&command[4], &param2, sizeof(param2));
  memcpy(&command[6], data, dataLength);

  uint16_t crc = crc16(&command[1], 8 - 3 + dataLength);
  memcpy(&command[6 + dataLength], &crc, sizeof(crc));
    
    uint8_t _status;
    _wire->beginTransmission(_address);   
   _wire->write(command, commandLength);
   _status = _wire->endTransmission(); 
    if (_status != 0) {
        return 0;
    }

  return 1; 
    
    
    
    
}

int Cryptochip::receiveResponse(void* response, size_t length)
{
  int retries = 20;
  size_t responseSize = length + 3; // 1 for length header, 2 for CRC
  byte responseBuffer[responseSize];

  while (_wire->requestFrom((uint8_t)_address, (size_t)responseSize, (bool)true) != responseSize && retries--);

  responseBuffer[0] = _wire->read();

  // make sure length matches
  if (responseBuffer[0] != responseSize) {
    return 0;
  }

  for (size_t i = 1; _wire->available(); i++) {
    responseBuffer[i] = _wire->read();
  }

  // verify CRC
  uint16_t responseCrc = responseBuffer[length + 1] | (responseBuffer[length + 2] << 8);
  if (responseCrc != crc16(responseBuffer, responseSize - 2)) {
    return 0;
  }
  
  memcpy(response, &responseBuffer[1], length);

  return 1;
}

uint16_t Cryptochip::crc16(const byte data[], size_t length)
{
  if (data == NULL || length == 0) {
    return 0;
  }

  uint16_t crc = 0;

  while (length) {
    byte b = *data;

    for (uint8_t shift = 0x01; shift > 0x00; shift <<= 1) {
      uint8_t dataBit = (b & shift) ? 1 : 0;
      uint8_t crcBit = crc >> 15;

      crc <<= 1;
      
      if (dataBit != crcBit) {
        crc ^= 0x8005;
      }
    }

    length--;
    data++;
  }

  return crc;
}


  uint16_t Cryptochip::decryptData(uint8_t cyphertext[], uint8_t plaintext[], uint16_t length) {
      
    for (int i = 0; i < length; i++) {
        plaintext[i] = cyphertext[i] ^ privSessionKey[i];
    }
    return 1;
      
  }
 uint16_t Cryptochip::encryptData(uint8_t plaintext[], uint8_t cyphertext[], uint16_t length) {
    
    
     
    for (int i = 0; i < 32; i++) {
        cyphertext[i] = plaintext[i] ^ privSessionKey[i];
    }
    
    if (length > 32) {
        uint8_t sessionKey2[32];
        sha256_func_host(privSessionKey, 32, sessionKey2);
        for (int i = 32; i < length; i++) {
            cyphertext[i] = plaintext[i] ^ sessionKey2[i-32];
        }
        
    }
    return 1;
      
  }

/* #ifdef CRYPTO_WIRE
Cryptochip ECCX08(CRYPTO_WIRE, 0x60);
#else
Cryptochip ECCX08(Wire, 0x60);
#endif */