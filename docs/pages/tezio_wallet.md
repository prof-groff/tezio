# Tezio Wallet

An Arduino-based hardware wallet for the Tezos blockchain. 

## Introduction

[Arduino](http://www.arduino.cc) is an ecosystem of open-source hardware and software tools for microcontroller-based electronics. It is popular among so-called “makers”, who have a technology-centric do-it-yourself (DIY) culture. Makers celebrate entrepreneurship, the capacity of individuals to create and innovate, and the ability of a community of like-minded developers to facilitate this process. Tezio Wallet turns an off-the-shelf Arduino board into a hardware wallet allowing users to confidently and securely take self-custody of their Tezos blockchain assets and participate in network transactions. Currently, two Arduino boards are supported, The MKR WiFi 1010 and the Nano 33 IoT. Both of these boards include a cryptographic co-processor (the Microchip ATECC508 and ATECC608 on the MKR WiFi 1010 and Nano 33 IoT, respectively) to securely store keys and accelerate certain cryptographic functions. There are many online stores from which an Arduino can be purchased, my favorite are [SparkFun](http://www.sparkfun.com), [Adafruit](http://www.adafruit.com), and [Mouser](http://www.mouser.com).

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
