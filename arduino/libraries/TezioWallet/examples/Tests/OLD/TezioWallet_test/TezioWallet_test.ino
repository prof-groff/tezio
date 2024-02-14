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

#include <Tezio.h>

const char* phrase[24] = {"motor", "jazz", "team", "food", "when", "coach", "reward", "hidden", "obtain", "faculty", "tornado", "crew", 
                          "toast", "inhale", "purchase", "conduct", "cube", "omit", "illness", "carbon", "ripple", "thank", "crew", "material"}; 

const uint8_t entropy[32] = {0x90, 0x6e, 0xef, 0x7a, 0xad, 0x6f, 0xa2, 0x59, 0x6e, 0x2b, 0x5b, 0x98, 0x8a, 0x37, 0x95, 0x99, 
                             0xae, 0x30, 0xe7, 0x6b, 0x89, 0x76, 0x35, 0x73, 0x4d, 0xc4, 0x91, 0x3b, 0xa5, 0xbf, 0x8c, 0xd4};

const char deriv_path[] = "m/44'/1729'/0'/2'"; // the default derivation path for tezos is "m/44'/1729'/0'/0'" 

void setup() {
  Serial.begin(9600);
  while (!Serial); delay(500); //short wait

  Serial.println("Generating Tezos wallet...");
  
  // TezioWallet walletOne(); // no entropy or phrase supplied - both are generated but are both kept secret
  // TezioWallet walletOne(entropy); // entropy supplied - mnemonic phrase generated from entropy but kept secret
  TezioWallet walletOne(phrase); // phrase supplied - entropy generated from phrase but kept secret
  // TezioWallet walletOne(phrase, deriv_path, sizeof(deriv_path)); // phrase supplied but use custom derivation path, custom derivation paths also work with supplied entropy or nothing

  Serial.println("Public key...");
  for (int i = 0; i < 32; i ++) {
    Serial.print(walletOne.public_key[i], HEX); Serial.print(' ');
  }
  Serial.println();
  Serial.println("Public key hash...");
  Serial.println(walletOne.public_key_hash);
  
}

void loop() {

}
