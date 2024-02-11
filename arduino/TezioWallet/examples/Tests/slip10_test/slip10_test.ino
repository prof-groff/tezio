/* 
Use this sketch to test the implemention of SLIP-0010 using test vectors 
at https://github.com/satoshilabs/slips/blob/master/slip-0010.md
*/

#include <Tezio.h>

uint8_t master_skcc[64];
char child_sk[65]; // 32 bytes plus null
uint8_t curve = SECP256K1; // ED25519, SECP256K1, or NISTP256
  char seed[] = "000102030405060708090a0b0c0d0e0f";
  char path[] = "m/0h/1/2h/2/1000000000";


void setup() {
  start_serial();
  seed_to_master_skcc(seed, sizeof(seed), master_skcc, curve);
  master_skcc_to_child_sk(master_skcc, path, sizeof(path), child_sk, curve);
  Serial.println(child_sk);
}

void loop() {
  delay(1); // do nothing
}
