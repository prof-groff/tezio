#include "Tezio_Config.h"


signingPolicies set_signing_policies() {

    signingPolicies sPolicy;

    sPolicy.tz3.policy[BLOCK]= 1;
    sPolicy.tz3.policy[PRE_ATTESTATION] = 1;
    sPolicy.tz3.policy[ATTESTATION] = 1; 

    // sPolicy.tz3.policy[TRANSFER] = 1;

    return sPolicy;

}