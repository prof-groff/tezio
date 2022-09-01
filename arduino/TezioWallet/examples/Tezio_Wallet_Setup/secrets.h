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


#ifndef SECRETS_H
#define SECRETS_H

/*
 * -- Test Vectors --
 * 
 * Mnemonic: "mule wise online wear hair sign wife media calm arctic diet tip special quarter season swarm robust apart other whale broken pistol hunt egg"
 * 
 * Password: "" 
 * 
 * Derivation Path: "m/44'/1729'/0'/0'"
 * 
 * Private Keys
 * Ed25519: 51 7B E5 EE 3E 34 7B E7 29 8C 5A C1 BC 9E 88 EC C3 E4 0 E9 0 4F F7 61 26 6E 60 CA C9 B1 0 34 
 * Secp256k1: 50 1A 71 D1 52 52 B1 DE 24 DB D5 69 CD FA 26 CD E4 9B EE 60 31 1F 26 EF A9 A9 33 B7 E2 17 4A 26 
 * NistP256: 8B F3 10 A0 A5 2E 5A 19 35 0 56 27 C9 ED 6B AD 9C A5 A6 8 99 27 3C BC 19 47 51 51 4 31 B 37 
 * 
 * Public Keys (compressed if applicable)
 * Ed25519: B3 65 D1 23 C 89 E9 50 48 3C 77 A8 D3 42 14 AE 5C C 13 4 B2 DE D0 2E 3F 55 3E 91 5C 8 2D 17 
 * Secp256k1: 3 C4 D6 41 C1 9E 8C 31 54 EB F5 F1 D8 F6 65 C4 A5 D 36 E1 AE E4 93 7E 16 8C 82 5 A0 EB 3C 80 8C 
 * NistP256: 3 10 5A 7D 89 A3 F6 C5 B3 69 1D D0 55 94 45 56 C9 85 80 41 F8 6D A3 91 B0 1C 83 89 11 5B 52 9 F6 
 * 
 * Public Key Hashes
 * Ed25519: tz1RecHxwZJmZY4dypq2KmvxKYgUBGJceH1v
 * Secp256k1: tz2Dy8HhPZZqmxVK5hE8Unc66fiWvqY8wFXN
 * NistP256: tz3MyarJihHrejsze59J2Seita7jYWDCJDPe
 * 
 */

char mnemonic[] = "mule wise online wear hair sign wife media calm arctic diet tip special quarter season swarm robust apart other whale broken pistol hunt egg";
char path[] = "m/44'/1729'/0'/0'"; // default derviation path for Tezos according to BIP44 and SLIP44
char password[] = "";

#endif
