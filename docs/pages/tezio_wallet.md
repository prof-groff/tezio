# Tezio Wallet

An Arduino-based hardware wallet for the Tezos blockchain. 

## Introduction

Tezio Wallet turns an off-the-shelf Arduino into a hardware wallet allowing users to confidently and securely take self-custody of their Tezos blockchain assets and participate in network transactions. Currently, two Arduino boards are supported, The MKR WiFi 1010 and the Nano 33 IoT. Both of these boards include a cryptographic co-processor (the Microchip ATECC508 and ATECC608 on the MKR WiFi 1010 and Nano 33 IoT, respectively) to securely store keys and accelerate certain cryptographic functions. 

## Getting Started

Setting up Tezio Wallet on your Arduino is a three step process. First, the Arduino IDE and library files installed, Next, the cryptographic co-processor is configured, provisioned with keys, and locked. Finally, the API software is installed.

### Step 1: Installation of Arduino IDE and Library Files

#### Get an Arduino MKR WiFi 1010 or Nano 33 IoT

There are many online stores from which an Arduino can be purchased, my favorite are [SparkFun](http://www.sparkfun.com), [Adafruit](http://www.adafruit.com), and [Mouser](http://www.mouser.com).

### Download and Install the Arduino IDE

The Arduino Integrated Development Environment (IDE) is useful for writing Arduino programs, called sketches, and uploading them to your Arduino board. It is available for Windows, macOS, and Linux under the software tab at [Arduino.cc](http://www.arduino.cc). The steps below are specific to the macOS version, but should be very similar if using other versions of the IDE. 

### Install Tezio Wallet Library and Dependencies

Download the TezioWallet.zip file from the [Tezio GitHub repository](https://github.com/prof-groff/tezio/tree/main/arduino). Open the Arduino IDE and use Sketch > Include Library > Add .ZIP Library... to install the library from the .zip file. Alternatively, the TezioWallet folder and its contents can be added manually to the Arduino libraries folder, which is usually My Documents\Arduino\libraries on Windows or Documents\Arduino\libraries on macOS. Next,  search for and install the following dependencies using Tools > Manage Libraries....

- ArduinoECCX08
- Crypto
- micro-ecc
