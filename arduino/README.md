## Tezio Wallet

Welcome to Tezio Wallet, an Arduino-based hardware wallet for the Tezos blockchain. Tezio Wallet is compatible with the Arduino MKR WiFi 1010 and the Arduino Nano 33 IoT, both of which include a cryptographic coprocessor to securely store keys and perform certain crytpographic functions. 

See the [Tezio Wallet Project Page](https://tezio.cc/pages/tezio_wallet.html) for installation notes and an API reference. 

## NOTES...
* Notes during development; helpful for me; not very orderly, but will turn into project docs someday...

### Keys Used During Master Secret Derivation

One of the steps in HD wallet creation is master-seed to master-key deviation. This involves HMAC-SHA512 using where the data is the master seed and the key is a character string based on the elliptic curve to be utilized later in the process. I know, and have verified, that for ed25519 the key is "ed25519 seed". According to the SLIP10 documentation posted [here](https://github.com/satoshilabs/slips/blob/master/slip-0010.md), the key for NIST P-256 (aka secp256r1) is "Nist256p1 seed" and the key for secp256k1 (Koblitz curve) is "Bitcoin seed". This last key is defined in BIP32. I'll assume these keys are used by the Tezos Ledger app and aim to verify. 

### Domains of Elliptic Curves

The three elliptic curves used in Tezos have valid private key domains close to 0 to 2<sup>256</sup> - 1 but they each actually have a more limited domains. For initial development I am going to ignore this fact and assume any random integer vetween 0 and 2<sup>256</sup> - 1 is valid key beacause the probability of randomly drawing a number that is not valid is very small. For secp256k1 the domain is integers between 1 and n-1 where
<code> n = 2<sup>256</sup> − 0x14551231950b75fc4402da1732fc9bebf</code>
For secp256r1 the domain is between 1 and n-1 where
<code> n = 2<sup>256</sup> − 2<sup>224</sup> + 2<sup>192</sup> − 0x4319055258e8617b0c46353d039cdaaf</code>
[Source](https://crypto.stackexchange.com/questions/30269/are-all-possible-ec-private-keys-valid)

Interestingly, the SLIP10 reference and [others](https://crypto.stackexchange.com/questions/60866/is-every-bytestring-a-valid-ed25519-private-key) say that any number between 0 (yes zero) and 2^256 - 1 is a valid private key for ed25519 but this makes no sense because the curve itself is a field defined by prime 2^255 - 19, and there is some business about "clamping" some bits to make the key valid. [Source](https://crypto.stackexchange.com/questions/71140/valid-private-keys-on-curve25519). My best guess here is that the implementation of ed25519 takes care of these invalid keys on the fly and any number between 0 and 2^256-1 works. 
 
### About Public Keys

For the ed25519 curve, public keys are 32 bytes. For secp255k1 and P256, public keys are 64 bytes, 32 for an x coordinate and 32 for a y coordinate. My understanding is that the y coordinate can be found from the x coordinate but occurs as y^2 so it can be positive or negative (above or below the x axis) so while the value doesn't need to be preserved whether it is even or odd needs to be preserved (don't understand what even/odd has to do with pos/neg). In compressed form  the public key is the x coordinate with a prefix of 0x02 if the y coordinate is even and 0x03 if it is odd.

### Installing and Running Octez

Octez is a suite of software that fully implements the Tezos blockchain. There are several fine tutorials out there for installing octez like [this one](https://tezos.gitlab.io/index.html)

### Useful Commands

octez-node run

octez-baker-Proxford run with local node ~/.tezos-node/ tezio_nistp256 --liquidity-baking-toggle-vote pass

gunicorn --bind 127.0.0.1:5000 tezio_signer:app

### Test Vectors

Mnemonic: "mule wise online wear hair sign wife media calm arctic diet tip special quarter season swarm robust apart other whale broken pistol hunt egg"

Password: "" 

Derivation Path: "m/44'/1729'/0'/0'"
 
Private Keys
 Ed25519: 51 7B E5 EE 3E 34 7B E7 29 8C 5A C1 BC 9E 88 EC C3 E4 0 E9 0 4F F7 61 26 6E 60 CA C9 B1 0 34 
 Secp256k1: 50 1A 71 D1 52 52 B1 DE 24 DB D5 69 CD FA 26 CD E4 9B EE 60 31 1F 26 EF A9 A9 33 B7 E2 17 4A 26 
 NistP256: 8B F3 10 A0 A5 2E 5A 19 35 0 56 27 C9 ED 6B AD 9C A5 A6 8 99 27 3C BC 19 47 51 51 4 31 B 37 
 
 Public Keys
 Ed25519: B3 65 D1 23 C 89 E9 50 48 3C 77 A8 D3 42 14 AE 5C C 13 4 B2 DE D0 2E 3F 55 3E 91 5C 8 2D 17 
 Secp256k1: 3 C4 D6 41 C1 9E 8C 31 54 EB F5 F1 D8 F6 65 C4 A5 D 36 E1 AE E4 93 7E 16 8C 82 5 A0 EB 3C 80 8C 
 NistP256: 3 10 5A 7D 89 A3 F6 C5 B3 69 1D D0 55 94 45 56 C9 85 80 41 F8 6D A3 91 B0 1C 83 89 11 5B 52 9 F6 
 
 Public Key Hashes
 Ed25519: tz1RecHxwZJmZY4dypq2KmvxKYgUBGJceH1v
 Secp256k1: tz2Dy8HhPZZqmxVK5hE8Unc66fiWvqY8wFXN
 NistP256: tz3MyarJihHrejsze59J2Seita7jYWDCJDPe

 ## Configure UDEV RULES for Arudino

 cd /etc/udev/rules.d/
 sudo nano 99-arduino.rules

 Add the following to 99-arduino.rules and Save

 SUBSYSTEM=="tty", KERNEL=="ttyACM[0-9]*", GROUP="dialout", MODE:="0666"

Run the following

sudo udevadm control --reload-rules
sudo udevadm trigger

# Octez Client and Node Setup

Install octez-client and octez-node and octez-baker following instructions [here](https://tezos.gitlab.io/introduction/howtoget.html)

## Configure and Run the Node

octez-node config init --network=ghostnet
octez-node config update --rpc-addr="localhost:8732" --net-addr="[::]:9732" --history-mode=rolling
octez-node snapshot import <FILE>
octez-node run

### Check if Node is Bootstrapped

octez-client bootstrapped

### Making the node persistent

systemctl enable octez-node.service
systemctl start octez-node.service

# Octez Client Setup

## Import Keys From Tezio Signer

octez-client import secret key <key_alias> http://localhost:5000/<tz_pkh>

## Import Authentification Key for Tezio Signer

octez-client import secret key <key_alias> unencrypted:<sk_b58_check>

octez-client set consensus key for <baker_key_alias> to <baker_consensus_key_alias>

## Run Baker

octez-baker-Proxford run with local node ~/.tezos-node/ tezio_nistp256 --liquidity-baking-toggle-vote pass