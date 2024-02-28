#include "Tezio_Config.h"


void set_signing_policies(policyStruct *policy) {

    // policyStruct policy[N_CURVES];

    policy[TZ3].operation[BLOCK]= 1;
    policy[TZ3].operation[PRE_ATTESTATION] = 1;
    policy[TZ3].operation[ATTESTATION] = 1; 

    // sPolicy.tz3.policy[TRANSFER] = 1;

    return;

}

void set_high_water_marks(hwmStruct *hwm) {

    hwm[TZ3].level[BLOCK-0x11] = 0;
    hwm[TZ3].round[BLOCK-0x11] = 0;

    hwm[TZ3].level[PRE_ATTESTATION-0x11] = 0;
    hwm[TZ3].round[PRE_ATTESTATION-0x11] = 0;

    hwm[TZ3].level[ATTESTATION-0x11] = 0;
    hwm[TZ3].round[ATTESTATION-0x11] = 0;

    return; 
}