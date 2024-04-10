# Tezio HSM

Tezio HSM is an Arduino-based hardware security module for the Tezos blockchain. Tezio HSM is currently compatible with the Arduino Nano 33 IoT and the Arduino MKR WiFi 1010, both of which include a cryptographic coprocessor (i.e., secure element) to securely store keys and perform certain crytpographic functions. 

# Contents

- [Introduction](#introduction)
- [Getting Started](#getting_started)
- [API Reference](#api_reference)

<a name="introduction"></a> 
# Introduction

[Arduino](http://www.arduino.cc) is an ecosystem of open-source hardware and software tools for microcontroller-based electronics. It is popular among so-called “makers”, who have a technology-centric do-it-yourself (DIY) culture. Makers celebrate entrepreneurship, the capacity of individuals to create and innovate, and the ability of a community of like-minded developers to facilitate this process. Tezio HSM turns an off-the-shelf Arduino board into a hardware wallet similar to a Ledger device allowing users to confidently and securely take self-custody of their Tezos blockchain assets and participate in network transactions. Currently, two Arduino boards are supported, The MKR WiFi 1010 and the Nano 33 IoT. Both of these boards include a cryptographic co-processor (the Microchip ATECC508 and ATECC608 on the MKR WiFi 1010 and Nano 33 IoT, respectively) to securely store keys and accelerate certain cryptographic functions. There are many online stores from which an these Arduino boards can be purchased, my favorites are [SparkFun](http://www.sparkfun.com), [Adafruit](http://www.adafruit.com), and [Mouser](http://www.mouser.com).

<a name="getting_started"></a> 
# Getting Started

Getting started with Tezio HSM requires that you first install the Arduino IDE and library files. Next, the cryptographic co-processor is provisioned. The last step is to configure and install the the Tezio API.

## Step 1: Installation of the Arduino IDE and Library Files

The steps below may be slightly different depending on the OS utilized. 

### Download and Install the Arduino IDE

The Arduino Integrated Development Environment (IDE) is used to both write Arduino programs, called sketches, and upload sketches to your Arduino board. It is available for Windows, macOS, and Linux under the software tab at [Arduino.cc](http://www.arduino.cc). 

### Install Support for Arduino SAMD Boards

Open the Arduino IDE, navigate to Tools > Board > Boards Manager..., and search for and install the Arduino SAMD Boards (32-bits ARM Cortex M0+) by Arduino, Version 1.8.14+ package. 

### (Linux Only) Configure Udev Rules for Arduino Devices

Udev is the Linux subsystem that detects when devices are connected and disconnected from your computer. In Ubuntu Linux it is necessary to configure the udev rules so Arduino devices can be programmed via the Arduino IDE. 

**Navigate to the udev rules directory and create a new rules file for Arduino devices.**

 cd /etc/udev/rules.d/
 sudo nano 99-arduino.rules

 **Add the following line to the new rules file.**

 SUBSYSTEM=="tty", KERNEL=="ttyACM[0-9]*", GROUP="dialout", MODE:="0666"

**Save the edits, exit, and run the following commands.**

sudo udevadm control --reload-rules
sudo udevadm trigger

### Install the Tezio Library and Dependencies

Download the [Tezio GitHub repository](https://github.com/prof-groff/tezio/tree/main) and copy the contents of the arduino/libraries folder to the Arduino libraries folder, which is usually My Documents/Arduino/libraries on Windows or Documents/Arduino/libraries on macOS and Ubuntu Linux. This will install the Tezio library and two dependencies.

Alternatively, zip the Tezio folder under arduino/libraries. Then, open the Arduino IDE and use Sketch > Include Library > Add .ZIP Library... to install the library from the .zip file. Then,  search for and install the dependencies using Tools > Manage Libraries....

- Crypto by Rhys Weatherley, Version 0.4.0+
- micro-ecc by Kenneth MacKay, Version 1.0.0+

Once the libraries are installed, restart the Arduino IDE before proceeding.

## Step 2: Configuring, Provisioning, and Locking the Cryptographic Co-Processor

### Open and Prepare the Setup Sketch

The Tezio library includes several example sketches to get started with Tezio HSM. Open the Arduino IDE and navigate to File > Examples > Tezio and open TezioHSM_Provision_Sketch. This will open three tabs in the IDE: the sketch, a configuration.h file, and a provision_secrets.h file. These example files are read only. In order to make and save changes, click the save button and make a copy of the sketch directory. The configuration.h file contains default configuration data for the cryptochip. Do not modify it. As the name suggests, the provision_secrets.h file contains secrets, specifically a mnemonic phrase, a read-write key used to encrypt communication between the microcontroller and the cryptographic coprocessor, a key used to authenticate signing requests from Octez, a derivation path, and a key derivation password. Keep your secrets secret. By default, a password is not used and the derivation path defaults to the standard path for the Tezos blockchain. If your aim is to set up your Tezio HSM to use a already existing Tezos account from popular wallets such as Kukai and Temple, enter your 12, 15, 18, 21, or 24 word phrase, password, and derivation path in provision_secrets.h. Otherwise a new 24 word menmonic phrase will be generated when the sketch is run. The provision_secrets.h file is thouroughly commented to help guide you further. 

### Upload and Run the Setup Sketch

Connect your Arduino to your computer via USB and navigate to Tools > Port to verify it was detected. You may have to manually select the port corresponding to your device. Next verify that your Arduino device is selected in the Tools > Board > Arduino SAMD menu so the IDE compiles for the correct device. Open the Serial Monitor using the button in the upper right corner or by navigating to Tools > Serial Monitor. Then, upload the sketch to your board using the Upload button or Tools > Upload. Once the sketch is uploaded it will begin running on the Arduino automatically. The sketch runs an interactive setup using the Serial Monitor to share data with the user and get user inputs. The process begins by loading the configuration data onto the Arduino's cryptographic co-processor. Once the configuration data is written to the device, the user has the option to lock the cofiguration zone. This must be done before the device can be used. After the device is configured, the sketch proceeds to derive HD wallet cryptographic keys from a user supplied mnemonic phrase specifice in the provision_secrets.h file, or if a mnemonic phrase isn't provided the sketch proceeds to derive a new 24 word phrase using entropy provided by the cryptochip's true random number generator. Mnemonic and key derivation are carried out using specifications outlined in the BIP-0039, BIP-0032, BIP-0044, SLIP-0044, and SLIP-0010. Secret keys are derived for all three elliptic curves supported by the Tezos blockchain: Ed25519, Secp256k1, and NIST P256 (Secp256r1). The secret keys, public keys, and the read/write key are written to the Arduino's cryptochip. The authentication key is also written. After keys are written, the user is given the option to lock the cryptochip's data zone. After the data zone is locked, clear writes of cryptographic secrets will no longer be possible. However, the device must be locked before use. After locking, the keys can be updated using the same provisioning sketch. However, changing the read/write key is not supported and the original read/write key must be used to perform encrypted writes to the HSM. 

## Step 3: Upload the API Sketch

Navigate to File > Examples > Tezio and open the TezioHSM_API.ino sketch. Save a copy of this sketch and edit api_secrets.h to include the same read/write key provisioned to the device earlier. The API sketch can be run in debug (interactive) mode using the Arduino IDE's Serial Monitor. However, the debug flag is set to false by default putting the device into listening mode. In this mode the device can be connected via USB to any host machine and recieve and send data via a serial connection. The API includes three HSM operations. **OP_GET_PK** retreives the public key or public key hash for any of the keys provisioned on the device. **OP_VERIFY** performs signature varification. **OP_SIGN** generates a signature for a message using one of the provisioned secret keys. By default, the API enables all HSM operations for all keys but the API includes the ability to disable specific HSM operations for certain keys using the **disable_hsm_op** method. Even if **OP_SIGN** is not disabled for a given key, all Tezos signing requests are refused by the API by default. Requests for specific operations types may be enabled via a separate policy according to the prefix byte (magic byte) that accompanies these operations using the **enable_tezos_op** method. Follow the documentation within the TezioHSM_API.ino sketch to configure the HSM, disabling forbidden HSM operations and enabling desired Tezos operation. Then compile and upload the skecth. Once the sketch is uploaded to the device, it will begin running and will restart whenever power is supplied to the device. That's it, your Tezio HSM is ready.

<a name="api_reference"></a> 
# API Reference

The API sketch invokes the TezioHSM_API class to expose certain cryptographic tools to the host device. Importantly, private (secret) keys never leave the device. In fact, the cryptochip implements hardware support for cryptographic functions using the NIST P256 curve so the NIST P256 secret key never leaves the cryptochip's secure element. The ED25519 and SECP256K1 secret keys may be retreived from the secure element by the microcontroller but all reads are encrypted using the read/write key provided by the user during setup. The hardware support for the NIST P256 key makes cryptographic functions involving this key significantly faster than those of the other supported curves. 

## Communication and Packets

Communication between the Tezio Wallet and a host computer is via a USB serial connection. Data is sent as packets of bytes. Packets sent from the host computer to the Tezio Wallet have four components, a prefix byte, a length byte, one or more body bytes, and two checksum bytes:

`packet = prefix [1 byte] + length [1 byte] + body [1 or more bytes] + checksum [2 bytes]`

The contents of the body depends on the command being sent but in general is is composed of an operation code byte (opCode), one or more parameter bytes, and data bytes.

`body = opCode [1 byte] + param1 [1 byte] + param2 [1 byte] + param3 [2 bytes] + data [1 or more bytes]`

The opCode is always required but some calls may not require data or all parameters. However, if data is sent then values for all parameters must also be included even if 0s are used as placeholders. Parameter 3 is represented in code as a 16-bit variable but is always sent over serial as two bytes with the the LSB first. Packets are constructed as follows: First the body is constructed. The length byte is the length of the body in bytes plus 3 to account for both the length byte itself and the checksum bytes. The length byte is prepended to the body and the checksum is calculated using a 16-bit cyclic redundancy check algorithm. The checksum is appended to the body LSB first. Finally the prefix byte is prepended. The prefix is always 0x03 and serves as a listening byte for the hardware wallet to detect incoming communication. 

Packets of bytes received by the host from the hardware wallet have the following structure:

`packet = length [1 byte] + body [1 or more bytes] + checksum [2 bytes]`

The contents of the body depends on the operation that was called and no prefix is needed since the host expects a prompt reply and doesn't need to listen for a reply to be sent.

## HSM Operations

### Get Public Key (OP_GET_PK)

Returns the public key for a specific curve. The returned key can be be raw bytes, compressed, base58 checksum encoding, or hashed (Tezos Address). 

<center>

| packet vars | value             |
|-------------|-------------------| 
| opCode      | 0x11              |
| param1      | curve/key alias   |
| param2      | public key format |
| param3      | -                 |
| data        | -                 |

| curve/key alias      | value |
|----------------------|-------|
| auth key (NIST P256) | 0x00  |
| Tezos Ed25519 key    | 0x01  |
| Tezos Secp256k1 key  | 0x02  |
| Tezos NIST P256 key  | 0x03  |

| public key format           | value |
|-----------------------------|-------|
| raw (32 or 64 bytes)        | 0x01  |
| compressed (32 or 33 bytes) | 0x02  |
| base58 checksum encoded     | 0x03  |
| hashed (Tezos address)      | 0x04  |

</center>

### Sign a Message (OP_SIGN)

Signs a message using the secret key for a specific curve and returns the signature. The message can be prehashed by the host system or sent as raw bytes. The default buffer size allows messages to be up to 1015 bytes in length. The returned signature can be raw bytes or base58 checksum encoded. This operaiton does not use param3 but a value must be included in the packet since data is included. 

| packet vars | value                    |
|-------------|--------------------------| 
| opCode      | 0x21                     |
| param1      | curve/key alias          |
| param2      | message/signature format |
| param3      | 0x0000                   |
| data        | message                  |

| curve/key alias      | value |
|----------------------|-------|
| auth key (NIST P256) | 0x00  |
| Tezos Ed25519 key    | 0x01  |
| Tezos Secp256k1 key  | 0x02  |
| Tezos NIST P256 key  | 0x03  |

| message format | signature format        | value |
|----------------|-------------------------|-------|
| hashed         | raw (64 bytes)          | 0x01  |
| hashed         | base58 checksum encoded | 0x02  |
| not hashed     | raw (64 bytes)          | 0x03  |
| not hashed     | base58 checksum encoded | 0x04  |

### Verify a Signature (OP_VERIFY)

Verifies that a signature is valid for a given message and specific curve. The message can be hashed or unhashed and the signature can be raw bytes or base58 checksum encoded. The data portion of the packet body is the message with the signature appended to it. Parameter 3 gives the message length and is not necessary if the message is pre-hashed because a hashed message is always 32 bytes long. The maximum message size depends on the format of the signature but the default buffer size allows for a message of at least 916 bytes. 

| packet cars | value                    |
|-------------|--------------------------| 
| opCode      | 0x22                     |
| param1      | curve/key alias          |
| param2      | message/signature format |
| param3      | message length           |
| data        | message + signature      |

| curve/key alias      | value |
|----------------------|-------|
| auth key (NIST P256) | 0x00  |
| Tezos Ed25519 key    | 0x01  |
| Tezos Secp256k1 key  | 0x02  |
| Tezos NIST P256 key  | 0x03  |

| message format | signature format        | value |
|----------------|-------------------------|-------|
| hashed         | raw (64 bytes)          | 0x01  |
| hashed         | vase58 checksum encoded | 0x02  |
| not hashed     | raw (64 bytes)          | 0x03  |
| not hashed     | base58 checksum encoded | 0x04  |
