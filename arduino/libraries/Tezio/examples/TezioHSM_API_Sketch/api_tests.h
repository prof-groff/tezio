#ifndef TESTS_H
#define TESTS_H

// CURVE/SLOT/KEY ALIASES
#define TZ3_AUTH 0
#define TZ1 1
#define TZ2 2
#define TZ3 3

// HSM OPERATIONS
#define OP_GET_PK 0x11
#define OP_SIGN 0x21
#define OP_VERIFY 0x22

// TEZOS OPERATIONS MAGIC BYTES
#define LEGACY_BLOCK 0x01
#define LEGACY_ENDORSEMENT 0x02
#define TRANSFER 0x03
#define AUTHENTICATED_SIGNING_REQUEST 0x04
#define MICHELSON_DATA 0x05
#define BLOCK 0x11
#define PRE_ATTESTATION 0x12
#define ATTESTATION 0x13

// OP_GET_PK RETURNED KEY FORMATS
#define PK_RAW_BYTES 0x01
#define PK_COMPRESSED_BYTES 0x02
#define PK_BASE58_CHECKSUM_ENCODED 0x03
#define PKH_TEZOS_ADDRESS 0x04

// OP_SIGN AND OP_VERIFY MESSAGE AND SIGNATURE FORMATS
#define MESSAGE_HASHED_SIG_RAW_BYTES 0x01
#define MESSAGE_HASHED_SIG_BASE58_CHECKSUM_ENCODED 0x02
#define MESSAGE_UNHASHED_SIG_RAW_BYTES 0x03
#define MESSAGE_UNHASHED_SIG_BASE58_CHECKSUM_ENCODED 0x04

void run_op_get_pk_test(TezioHSM_API myWallet, uint8_t curve, uint8_t mode); 
void run_op_sign_and_verify_test(TezioHSM_API myWallet, uint8_t curve, uint8_t mode);
void set_test_configuration(TezioHSM_API myWallet);
void run_tests(TezioHSM_API myWallet); 

#endif
