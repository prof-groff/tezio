# Tezio Wallet

An Arduino-based hardware wallet for the Tezos blockchain. 

## Contents

- [Introduction](#introduction)
- [Getting Started](#getting_started)
- [API Reference](#api_reference)

<a name="introduction"></a> 
## Introduction

[Arduino](http://www.arduino.cc) is an ecosystem of open-source hardware and software tools for microcontroller-based electronics. It is popular among so-called “makers”, who have a technology-centric do-it-yourself (DIY) culture. Makers celebrate entrepreneurship, the capacity of individuals to create and innovate, and the ability of a community of like-minded developers to facilitate this process. Tezio Wallet turns an off-the-shelf Arduino board into a hardware wallet allowing users to confidently and securely take self-custody of their Tezos blockchain assets and participate in network transactions. Currently, two Arduino boards are supported, The MKR WiFi 1010 and the Nano 33 IoT. Both of these boards include a cryptographic co-processor (the Microchip ATECC508 and ATECC608 on the MKR WiFi 1010 and Nano 33 IoT, respectively) to securely store keys and accelerate certain cryptographic functions. There are many online stores from which an Arduino can be purchased, my favorite are [SparkFun](http://www.sparkfun.com), [Adafruit](http://www.adafruit.com), and [Mouser](http://www.mouser.com).

<a name="getting_started"></a> 
## Getting Started

Setting up Tezio Wallet on your Arduino is a three step process. First, the Arduino IDE and library files installed, Next, the cryptographic co-processor is configured, provisioned with keys, and locked. Finally, the API software is installed.

### Step 1: Installation of the Arduino IDE and Library Files

#### Download and Install the Arduino IDE

The Arduino Integrated Development Environment (IDE) is useful for writing Arduino programs, called sketches, and uploading them to your Arduino board. It is available for Windows, macOS, and Linux under the software tab at [Arduino.cc](http://www.arduino.cc). The steps below are specific to the macOS version, but should be very similar if using other versions of the IDE. 

#### Install Tezio Wallet Library and Dependencies

Download the TezioWallet.zip file from the [Tezio GitHub repository](https://github.com/prof-groff/tezio/tree/main/arduino). Open the Arduino IDE and use Sketch > Include Library > Add .ZIP Library... to install the library from the .zip file. Alternatively, the TezioWallet folder and its contents can be added manually to the Arduino libraries folder, which is usually My Documents\Arduino\libraries on Windows or Documents\Arduino\libraries on macOS. Next,  search for and install the following dependencies using Tools > Manage Libraries....

- ArduinoECCX08
- Crypto
- micro-ecc

Once the libraries are installed, restart the Arduino IDE before proceeding.

### Step 2: Configuring, Provisioning, and Locking the Cryptographic Co-Processor

#### Open and Prepare the Setup Sketch

The Tezio Wallet library includes several example sketches. Open the Arduino IDE and navigate to File > Examples > TezioWallet and open the TezioWallet_Setup.ino sketch. This will open three tabs in the IDE: the sketch, a configuration.h file, and a secrets.h file. The configuration.h file contains default configuration data for the cryptochip. Do not modify it. As the name suggests, the secrets.h file contains secrets, specifically a mnemonic phrase, a key derivation path, and a key derivation password. Keep your secrets secret. By default, a password is not used and the derivation path defaults to the standard path for the Tezos blockchain. If your aim is to set up your Tezio Wallet to use a already existing Tezos account, enter your 12, 15, 18, 21, or 24 word phrase, password, and derivation path in secrets.h. Otherwise a new 24 word menmonic phrase will be generated when the sketch is run. Near the top of the sketch is a read/write key used by the system later to allow the device to perform encrypted reads and writes to certain data slots of the cryptochip after it is locked. This can be changed to any 32 bytes value, so long as the same value is also used in the TezioWallet_API.ino sketch later. Save any changes before proceeding.

#### Upload and Run the Setup Sketch

Connect your Arduino to your computer via USB and navigate to Tools > Port to verify it was detected. You may have to manually select the port corresponding to your device. Next verify that your Arduino device is selected in the Tools > Board > Arduino SAMD menu so the IDE compiles for the correct device. Open the Serial Monitor using the button in the upper right corner or by navigating to Tools > Serial Monitor. Then, upload the sketch to your board using the Upload button or Tools > Upload. Once the sketch is uploaded it will begin running on the Arduino automatically. The sketch runs an interactive setup using the Serial Monitor to share data with the user and get user inputs. The process begins by loading the configuration data onto the Arduino's cryptographic co-processor. Once the configuration data is written to the device, the user has the option to lock the cofiguration zone. This must be done before the device can be used. After the device is configured, the sketch proceeds to derive HD wallet cryptographic keys from a user supplied mnemonic phrase specifice in the secrets.h file, or if a mnemonic phrase isn't provided the sketch proceeds to derive a new 24 word phrase using entropy provided by the cryptochip's true random number generator. Mnemonic and key derivation are carried out using specifications outlined in the BIP-0039, BIP-0032, BIP-0044, SLIP-0044, and SLIP-0010. Secret keys are derived for all three elliptic curves supported by the Tezos blockchain: Ed25519, Secp256k1, and NIST P256 (Secp256r1). The secret keys, derived public keys, and the user supplied read/write key are written to the Arduino's cryptochip. After keys are written, the user is given the option to lock the cryptochip's data zone. After the data zone is locked, clear writes of cryptographic secrets will no longer be possible. The device must be locked before use.

### Step 3: Upload the API Sketch

Navigate to File > Examples > TezioWallet and open the Tezio_Wallet_API.ino sketch. This sketch can be run in debug (interactive) mode using the Arduino IDE's Serial Monitor. However, debug flag to set to false by default putting the device into listening mode. In this mode the device can then be connected via USB to any host machine and recieve and send data via a serial connection. Once the sketch is uploaded to the device, it will begin running and will restart whenever power is supplied to the device. That's it, your Tezio Wallet is ready.

<a name="api_reference"></a> 
## API Reference

The API sketch invokes the TezioWallet_API class to expose certain cryptographic tools to the host device. Importantly, private (secret) keys never leave the device. In fact, the cryptochip implements hardware support for cryptographic functions using the NIST P256 curve so the NIST P256 secret key never leaves the cryptochip's secure element. This hardware support also means that cryptographic functions involving the NIST P256 curve are much faster than those of the other supported curves. See the .ipynb included in the [GitHub repository](https://github.com/prof-groff/tezio/tree/main/arduino) for example interactions with a Tezio Wallet using Python.

### Communication and Packets

Communication between the Tezio Wallet and a host computer is via a USB serial connection. Data is sent as packets of bytes. Packets sent from the host computer to the Tezio Wallet have four components, a prefix byte, a length byte, one or more body bytes, and two checksum bytes:

`packet = prefix [1 byte] + length [1 byte] + body [1 or more bytes] + checksum [2 bytes]`

The contents of the body depends on the command being sent but in general is is composed of an operation code byte (opCode), one or more parameter bytes, and data bytes.

`body = opCode [1 byte] + param1 [1 byte] + param2 [1 byte] + param3 [2 bytes] + data [1 or more bytes]`

The opCode is always required but some calls may not require data or all parameters. However, if data is sent then values for all parameters must also be included even if 0s are used as placeholders. Parameter 3 is represented in code as a 16-bit variable but is always sent over serial as two bytes with the the LSB first. Packets are constructed as follows: First the body is constructed. The length byte is the length of the body in bytes plus 3 to account for both the length byte itself and the checksum bytes. The length byte is prepended to the body and the checksum is calculated using a 16-bit cyclic redundancy check algorithm. The checksum is appended to the body LSB first. Finally the prefix byte is prepended. The prefix is always 0x03 and serves as a listening byte for the hardware wallet to detect incoming communication. 

Packets of bytes received by the host from the hardware wallet have the following structure:

`packet = length [1 byte] + body [1 or more bytes] + checksum [2 bytes]`

The contents of the body depends on the operation that was called and no prefix is needed since the host expects a prompt reply and doesn't need to listen for a reply to be sent.

### Operations

#### Get Public Key (op_get_pk)

Returns the public key for a specific curve. The returned key can be be raw bytes, compressed, base58 checksum encoding, or hashed (Tezos Address). 

| Packet Vars | Value |
|-------------|-------| 
| opCode      | 0x11  |
| param1      | curve |
| param2      | mode  |
| param3      | -     |
| data        | -     |

| curve | ECC curve |
|-------|-----------|
| 0x01  | Ed25519   |
| 0x02  | Secp256k1 |
| 0x03  | NIST P256 |

| mode | Public Key Format           |
|------|-----------------------------|
| 0x01 | Raw (32 or 64 bytes)        |
| 0x02 | Compressed (32 or 33 bytes) |
| 0x03 | Base58 Checksum Encoded     |
| 0x04 | Hashed (Tezos Address)      |

#### Sign (op_sign)

Signs a message using the secret key for a speciric curve. The message can be prehashed by the host system or sent as raw bytes. The returned signature can be raw bytes or base58 checksum encoded. This operaiton does not use param3 but a value must be included in the packet since data is included. 

| Packet Vars | Value  |
|-------------|--------| 
| opCode      | 0x21   |
| param1      | curve  |
| param2      | mode   |
| param3      | 0x0000 |
| data        | message|

| curve | ECC curve |
|-------|-----------|
| 0x01  | Ed25519   |
| 0x02  | Secp256k1 |
| 0x03  | NIST P256 |

| mode | message hashed | signature format        |
|------|----------------|-------------------------|
| 0x01 | yes            | Raw (64 bytes)          |
| 0x02 | yes            | Base58 Checksum Encoded |
| 0x03 | no             | Raw (64 bytes)          |
| 0x04 | no             | Base58 Checksum Encoded |

#### Verify (op_verify)

Verifies that a signature is valid for a given message and specific curve. The message can be hashed or unhashed and the signature can be raw bytes or base58 checksum encoded. The data portion of the packet body is the message with the signature appended to it. Parameter 3 gives the message length and is not necessary if the message is pre-hashed because a hashed message is always 32 bytes long. 

| Packet Vars | Value              |
|-------------|--------------------| 
| opCode      | 0x22               |
| param1      | curve              |
| param2      | mode               |
| param3      | message length     |
| data        | message + signature|

| curve | ECC curve |
|-------|-----------|
| 0x01  | Ed25519   |
| 0x02  | Secp256k1 |
| 0x03  | NIST P256 |

| mode | message hashed | signature format        |
|------|----------------|-------------------------|
| 0x01 | yes            | Raw (64 bytes)          |
| 0x02 | yes            | Base58 Checksum Encoded |
| 0x03 | no             | Raw (64 bytes)          |
| 0x04 | no             | Base58 Checksum Encoded |
