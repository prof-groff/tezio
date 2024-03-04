#ifndef TezioHSM_Config_H
#define TezioHSM_Config_H

#include <Arduino.h>
#include "constants.h"

// MAGIC BYTES
#define LEGACY_BLOCK 0x01
#define LEGACY_ENDORSEMENT 0x02
#define TRANSFER 0x03
#define AUTHENTICATED_SIGNING_REQUEST 0x04
#define MICHELSON_DATA 0x05
#define BLOCK 0x11
#define PRE_ATTESTATION 0x12
#define ATTESTATION 0x13

// PARAMETERS FOR ALLOCATING MEMORY
#define N_OPERATIONS 0x13 // this uses more space then needed but is convenient
#define N_BAKING_OPERATIONS 3 // if indeces are used to access, need to subtract 0x11

typedef struct {
    uint32_t level[N_BAKING_OPERATIONS] = {0};
    uint32_t round[N_BAKING_OPERATIONS] = {0};
} hwmStruct; 

typedef struct {
    uint8_t operation[N_OPERATIONS] = {0};
} policyStruct; 

void set_signing_policies(policyStruct *policy);
void set_high_water_marks(hwmStruct *hwm);

#endif 