/*

Default ATECCX08A Configuration Zone Data for Tezio Wallet

SLOTS 0-3: P256 Private Keys, Secret, No Reads, Encrypted Writes
SLOTS 4-7: Non P256 Private Keys (secp256k1 or ed25519 keys), Secret, Encrypted Reads, Encrypted Writes
SLOTS 8 and 9: Data, Clear Reads, Clear Writes
SLOT 10: Read/Write Key, Non P256 Private Key, Secret, Entrypted Reads, Encrypted Writes
SLOTS 11-14: Data, Clear Reads, Clear Writes, Intended for ECC Public Key Storage
SLOT 15: Data, Clear Reads, Clear Writes

Bits are set so the ATECC608 on the NANO 33 IoT opperate like the ATECC508 on the MKR WiFI 1010.

*/

#ifndef ATECCX08_CONFIGURATION_H
#define ATECCX08_CONFIGURATION_H

const byte CRYPTOCHIP_CONFIG[128] = {
  // Bytes 0 through 15 are read only
  0x00, 0x00, 0x00, 0x00, // SN<0:3>
  0x00, 0x00, 0x00, 0x00,  // RevNum
  0x00, 0x00, 0x00, 0x00, 0x00, // SN[4:8]
  0x00, // Reserved
  0x00, // I2C_Enable, Bit 0 is 1 if the device operates in I2C interface mode                 
  0x00, // Reserved 

  // Begin writable bytes
  0xC0, // I2C Address, default: 0xC0
  0x00, // Reserved
    
  // OTPmode
  #if defined(ARDUINO_SAMD_NANO_33_IOT)
  0x00, // CountMatch
  #else
  0x55, // 0x55 is consumption mode
  #endif
    
  0x00, // ChipMode
  
  // SlotConfig - Bytes 20 through 51
  0x87, 0x6A, // Secret ECC P256 Private Key, Encrypted Writes Using KeyID 0b1010 (10), Internal and External Signatures
  0x87, 0x6A, 
  0x87, 0x6A,
  0x87, 0x6A, 
  0xCA, 0x6A, // Other Privite Keys, Encrypted Reads and Writes using KeyID 0b1010 (10)
  0xCA, 0x6A,
  0xCA, 0x6A, 
  0xCA, 0x6A,
  0x00, 0x00, // Large Data, Clear Reads and Writes
  0x00, 0x00, // Clear Reads and Writes
  0x80, 0x6A, // Read/Write Key, No Reads, Encrypted Writes Using Itself (10)
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
  
  // KeyConfig
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
