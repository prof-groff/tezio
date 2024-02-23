#ifndef TEZIO_CONFIG_H
#define TEZIO_CONFIG_H

#include <Arduino.h>

// MAGIC BYTES
#define LEGACY_BLOCK 0x01
#define LEGACY_ENDORSEMENT 0x02
#define TRANSFER 0x03
#define AUTHENTICATED_SIGNING_REQUEST 0x04
#define MICHELSON_DATA 0x05
#define BLOCK 0x11
#define PRE_ATTESTATION 0x12
#define ATTESTATION 0x13

typedef struct {
    uint8_t policy[0x13] = {0};
} magicBytes;

typedef struct {
    magicBytes tz1, tz2, tz3, tz3_auth;
} signingPolicies; 

signingPolicies set_signing_policies(); 


#endif 