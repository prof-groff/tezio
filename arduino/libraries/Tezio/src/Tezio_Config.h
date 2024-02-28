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

// Curves/Pkhs
#define TZ1 1
#define TZ2 2
#define TZ3 3
#define TZ3_AUTH 4

#define N_CURVES 5 // space for all curves
#define N_OPERATIONS 0x13 // space for all operations
#define N_BAKING_OPERATIONS 3

// tz1.watermark.level[magicByte - 0x11]
// tz1.watermark.round[magicByte - 0x11]

// tz1.policy.authRequired


typedef struct {
    uint32_t level[N_BAKING_OPERATIONS] = {0};
    uint32_t round[N_BAKING_OPERATIONS] = {0};
} hwmStruct; 


typedef struct {
    uint8_t operation[N_OPERATIONS] = {0};
} policyStruct; 




/* typedef struct {
    uint8_t policy[0x13] = {0};
} magicBytes;

typedef struct {
    magicBytes tz1, tz2, tz3, tz3_auth;
} signingPolicies; 

signingPolicies set_signing_policies(); */

void set_signing_policies(policyStruct *policy);
void set_high_water_marks(hwmStruct *hwm);


#endif 