# Tezio 

Tezio (tez-eye-oh) develops open-source software and hardware tools for the Tezos blockchain. In particular, the focus is on development of tools that enable low-cost Arduino or Arduino-compatible devices to interact with Tezos. 

## About Arduino

Arduino is an ecosystem of open-source hardware and software that facilitates the rapid development of embedded electronic devices and physical computers that sense and respond to environmental stimuli. Arduino is an important tool of makers, a technology-centric DIY community that celebrates entrepreneurship and recognizes the capacity of individuals to create and innovate as part of a culture of open collaboration. 

## Projects

### Tezio HSM

Tezio HSM is a hardware security module (HSM) that includes a secure element to safely store and make use of crytographic keys and software tools to provision and use the HSM. The HSM makes use of either the Arduino Nano 33 IoT or the Arduino MKR WIFI 1010.

### Tezio Signer

Tezio Signer is a Python Flask application that handles Tezos signing requests from Octez. Signing requests are validated against a security and signing policy then forwarded to a Tezio HSM connected via USB.

### Tezio Tools

Tezio Tools are a collection of Python scripts and Tezos smart contracts written in Ligo or SmartPy. 

## License

[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)

