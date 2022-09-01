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

/* Default ATECCX08A Configuration Zone Data for Tezio Wallet. This data will configure
the cryptochip data slots as follows:

SLOTS 0-3: P256 Private Keys, Secret, No Reads, Encrypted Writes
SLOTS 4-7: Non P256 Private Keys (secp256k1 or ed25519 keys), Secret, Encrypted Reads, Encrypted Writes
SLOTS 8 and 9: Data, Clear Reads, Clear Writes
SLOT 10: Read/Write Key, Non P256 Private Key, Secret, Encrypted Writes
SLOTS 11-14: Data, Clear Reads, Clear Writes, Intended for ECC Public Key Storage
SLOT 15: Data, Clear Reads, Clear Writes

Preprocessor directives are such to set relevant bits so the newer ATECC608 on the NANO 33 IoT opperates 
like the ATECC508 on the MKR WiFI 1010. */

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

const byte CryptochipConfiguration[128] = {
  
  // READ ONLY BYTES [0:15]
  0x00, 0x00, 0x00, 0x00, // Serial Number [0:3]
  0x00, 0x00, 0x00, 0x00,  // Revision Number
  0x00, 0x00, 0x00, 0x00, 0x00, // Serial Number [4:8]
  0x00, // Reserved
  0x00, // I2C Enable - bit 0 is 1 if the device operates in I2C interface mode                 
  0x00, // Reserved 

  // BEGIN WRITABLE BYTES
  0xC0, // I2C Address, default: 0xC0
  0x00, // Reserved
    
  // OTP mode
  #if defined(ARDUINO_SAMD_NANO_33_IOT)
  0x00, // CountMatch
  #else
  0x55, // 0x55 is consumption mode
  #endif
    
  0x00, // ChipMode
  
  // SLOT CONFIG BYTES [20:51] 
  // each slot from 0 to 15 has two slot config bytes in sequential order
  // slots 0, 1, 2, and 3
  0x87, 0x6A, // Secret ECC P256 Private Key, Encrypted Writes Using KeyID 0b1010 (10), Internal and External Signatures
  0x87, 0x6A, 
  0x87, 0x6A,
  0x87, 0x6A, 
  // slots 4, 5, 6, and 7
  0xCA, 0x6A, // Other Privite Keys, Encrypted Reads and Writes using KeyID 0b1010 (10)
  0xCA, 0x6A,
  0xCA, 0x6A, 
  0xCA, 0x6A,
  // slots 8, 9, and 10
  0x00, 0x00, // More Space for Large Data, Clear Reads and Writes
  0x00, 0x00, // Clear Reads and Writes
  0x80, 0x6A, // Read/Write Key, No Reads, Encrypted Writes Using Itself (10)
  // slots 11, 12, 13, 14, and 15
  0x00, 0x00, // Clear Reads and Writes
  0x00, 0x00,
  0x00, 0x00,
  0x00, 0x00, 
  0x00, 0x00,
  
  // Counter<0>
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
  // Counter<1>
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
  // LastKeyUse
  #if defined(ARDUINO_SAMD_NANO_33_IOT)
  0x00, // UseLock
  0x00, // VolatileKey permission
  0x00, 0x00, // SecureBoot
  0x00, // kdfIVLoc
  0x00, 0x00, // kdfIVStr
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved, must be zero
  #else
  // LastKeyUse
  0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF,
  #endif
    
  // Write via commands only - start
  // UserExtra
  0x00, 
  // Selector for 508 and UserExtraAdd for 608
  0x00,
  // LockValue
  0x55,
  // LockConfig
  0x55,
  // SlotLocked
  0xFF, 0xFF,
  // Write via commands only - end
  // RFU for 508 and ChipOptions for 608
  0x00, 0x00,
  // X509format
  0x00, 0x00, 0x00, 0x00,
  
  // KEY CONFIG BYTES
  // two bytes for each of the 16 data slots.
  0x33, 0x00, // Private P256 Key
  0x33, 0x00, 
  0x33, 0x00, 
  0x33, 0x00, 
  0x3C, 0x00, // Other Secret Keys
  0x3C, 0x00,
  0x3C, 0x00,
  0x3C, 0x00,
  0x3C, 0x00, // Data
  0x3C, 0x00, 
  0x7C, 0x00, // Read/Write Key, ReqRand bit set
  0x3C, 0x00, // Data
  0x3C, 0x00,
  0x3C, 0x00,
  0x3C, 0x00,
  0x3C, 0x00
};

#endif
