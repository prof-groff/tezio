#include <Tezio.h>

// BIP-0039 test vectors using the password TREZOR can be found at https://github.com/trezor/python-mnemonic/blob/master/vectors.json

char entropy_str[] = "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f";
char password[] = "TREZOR";

uint8_t entropy[(sizeof(entropy_str)-1)/2];
char mnemonic[24][10];
char mnemonic_string[10*24];
uint8_t seed[64];

void setup() {
  start_serial();

  hex_chars_to_byte_array(entropy_str, sizeof(entropy_str), entropy, sizeof(entropy));
  print_hex_data(entropy, sizeof(entropy));

  uint16_t n_words = entropy_to_mnemonic(entropy, sizeof(entropy), mnemonic);
  uint16_t mnemonic_string_length = mnemonic_to_string(mnemonic, n_words, mnemonic_string);
  
  Serial.println(mnemonic_string);

  mnemonic_string_to_seed(mnemonic_string, mnemonic_string_length, seed, password, sizeof(password), 2048);
  print_hex_data(seed, sizeof(seed));

}

void loop() {
  delay(1); // do nothing
}
