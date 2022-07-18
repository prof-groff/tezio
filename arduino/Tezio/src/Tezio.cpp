#include "Tezio.h"

#if defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT)
#include <ArduinoECCX08.h>
#endif

#define MNEMONIC_LENGTH 24

uint8_t ED25519_KEY[] = "ed25519 seed";
uint8_t SECP256K1_KEY[] = "Bitcoin seed";
uint8_t NISTP256_KEY[] = "Nist256p1 seed";


void TezioWallet::store_mnemonic(const char* mnemonic[]) {
    char (*p)[10] = secret_mnemonic; // pointer
    for (uint16_t i = 0; i < MNEMONIC_LENGTH; i++) {
        strcpy(*p++, mnemonic[i]);
    }
}

void TezioWallet::store_mnemonic_from_serial() {
    char (*p)[10] = secret_mnemonic; // pointer
    if (!Serial) {
        Serial.begin(9600);
        while(!Serial);
    }
    int _index = 0;
    char _buffer[10]; 
    int _cursor;
    while (_index < MNEMONIC_LENGTH) {
        Serial.print("Enter word #"); Serial.println(_index+1);
        while (Serial.available() == 0); // wait
        _cursor = 0; // reset cursor
        while (Serial.available() > 0) {
            _buffer[_cursor] = Serial.read();
            _cursor ++;
            delay(10);
        }
        _buffer[_cursor] = '\0'; // insert null character to terminate
        Serial.println(_buffer);
        strcpy(*p++, _buffer);
        _index++;
    }
}

void TezioWallet::store_deriv_path(const char* path, uint16_t path_length) {
    deriv_path_length = path_length;
    deriv_path = (char*)malloc(deriv_path_length);
    strcpy(deriv_path, path);
    
}

void TezioWallet::generate_entropy() {
    #if defined(ARDUINO_SAMD_MKRWIFI1010) || defined(ARDUINO_SAMD_NANO_33_IOT)
    ECCX08.random(secret_entropy, sizeof(secret_entropy));
    #else
    randomSeed(analogRead(0)); // try to get some randomness from the system
    for (uint16_t i = 0; i < sizeof(secret_entropy); i ++) {
        secret_entropy[i] = random(0, 256); 
    }
    #endif
}

void TezioWallet::generate_mnemonic_from_entropy() {
    entropy_to_mnemonic(secret_entropy, 32, secret_mnemonic);
    secret_mnemonic_string_length = mnemonic_to_string(secret_mnemonic, MNEMONIC_LENGTH, secret_mnemonic_string);
}

void TezioWallet::generate_master_seed(uint8_t *password, uint16_t passwordLength) {
    uint8_t saltBase[] = "mnemonic";
    uint8_t saltBaseLength = sizeof(saltBase)-1; // ignore null terminator
    uint16_t saltLength = saltBaseLength + passwordLength;
    uint8_t salt[saltLength];
    
    memcpy(&salt[0], &saltBase[0], saltBaseLength);
    
    if (password) {
        memcpy(&salt[saltBaseLength], &password[0], passwordLength); 
    }
    
    uint16_t c = 2048;
    uint8_t mnemonic_string_bytes[secret_mnemonic_string_length]; // convert mnemonic string from char to uint8_t
    memcpy(mnemonic_string_bytes, secret_mnemonic_string, secret_mnemonic_string_length);
    pbkdf2_hmac_sha512(mnemonic_string_bytes, secret_mnemonic_string_length - 1, salt, saltLength, c, MASTER_SEED_SIZE, secret_master_seed);
}

void TezioWallet::generate_master_secret_key_and_chain_code(uint8_t curve) {
    uint8_t *key;
    uint16_t keyLength;
    switch(curve) {
       
        case ED25519:
            key = ED25519_KEY;
            keyLength = sizeof(ED25519_KEY)-1; // ignore null terminator
            break;
        case SECP256K1:
            key = SECP256K1_KEY;
            keyLength = sizeof(SECP256K1_KEY)-1;
            break;
        case NISTP256:
            key = NISTP256_KEY;
            keyLength = sizeof(NISTP256_KEY)-1;
            break;
        default:
            key = ED25519_KEY;
            keyLength = sizeof(ED25519_KEY)-1;
    }
    
    while(1) {
        hmac_sha512(key, keyLength, secret_master_seed, MASTER_SEED_SIZE, master_skcc);
        uint8_t sk[32];
        memcpy(&sk[0], &master_skcc[0], 32);
        if(key_is_valid(sk, sizeof(sk), curve)) { // if the key is not valid then hash hash the previous result again
            break;
        }
        else {
            memcpy(&secret_master_seed[0], &master_skcc[0], 64);
        }
    }
}

void TezioWallet::generate_child_secret_key_and_chain_code(uint8_t curve) {
    uint16_t n_indeces;
    n_indeces = derivation_path_preprocess(deriv_path, deriv_path_length - 1);
    uint32_t indeces[n_indeces];
    derivation_path_to_indeces(deriv_path, deriv_path_length - 1, indeces, n_indeces);
    uint8_t parent_skcc[64];
    memcpy(child_skcc, master_skcc, 64); // copy master sk cc to child sk cc
    for (uint16_t i = 0; i < n_indeces; i++) {
        memcpy(parent_skcc, child_skcc, 64); // copy previous child to parent
        derive_child_skcc_from_parent(parent_skcc, indeces[i], child_skcc, curve);
    } 
}

void TezioWallet::generate_public_key_ed25519() {
    uint8_t sk[32];
    memcpy(sk, child_skcc, 32); // first 32 bytes
    Ed25519::derivePublicKey(public_key,  sk);
}

void TezioWallet::generate_public_key(uint8_t curve) {
    uint8_t sk[32];
    uint8_t pk[64];
    memcpy(sk, child_skcc, 32); // first 32 bytes is the secret private key
    
    switch(curve) {
       
        case ED25519:
            {
            Ed25519::derivePublicKey(public_key,  sk); 
            break;
            }
        case SECP256K1:
            {
            const struct uECC_Curve_t * curve_secp256k1 = uECC_secp256k1();
            uECC_compute_public_key(sk, pk, curve_secp256k1);
            memcpy(&public_key_SECP256K1[1], &pk[0], 32);
            if (pk[63]%2) { // odd
                public_key_SECP256K1[0] = 0x03;
            }
            else {
                public_key_SECP256K1[0] = 0x02;
            }
          
            break;
            }
        case NISTP256: // CAN BE IMPLIMENTED IN HARDWARE ONCE PRIVATE KEY IS STORED
            {
            const struct uECC_Curve_t * curve_p256 = uECC_secp256r1();
            uECC_compute_public_key(sk, pk, curve_p256);
            memcpy(&public_key_NISTP256[1], &pk[0], 32);
            if (pk[63]%2) { // odd
                public_key_NISTP256[0] = 0x03;
            }
            else {
                public_key_NISTP256[0] = 0x02;
            }
            break;
            }
        default:
            Ed25519::derivePublicKey(public_key,  sk); 
    }
    
}


void TezioWallet::generate_public_key_hash() {

    BLAKE2b blake2b; 
    uint8_t pkhash[20];
    blake2b.reset(20);
    blake2b.update(public_key, sizeof(public_key));
    blake2b.finalize(pkhash, 20);
    uint8_t prefix[3] = {0x06, 0xa1, 0x9f};
    uint8_t tzpkhash[3 + sizeof(pkhash)];
    memcpy(&tzpkhash[0], &prefix[0], 3);
    memcpy(&tzpkhash[3], &pkhash[0], sizeof(pkhash));
    uint8_t sha256a[32];
    uint8_t sha256b[32]; // apply sha256 twice
    sha256_func_host(tzpkhash, 23, sha256a);
    delay(100);
    sha256_func_host(sha256a, 32, sha256b);
    uint8_t tzaddress[27];
    memcpy(&tzaddress[0], &tzpkhash[0], 23);
    memcpy(&tzaddress[23], &sha256b[0], 4);
    memset(public_key_hash, '\0', sizeof(public_key_hash));
    size_t outlength = base58_func(tzaddress, sizeof(tzaddress), public_key_hash);

}



TezioWallet::TezioWallet() {
    
    // GENERATE SECRET ENTROPY
    generate_entropy();
    
    // GENERATE SECRET MNEMONIC PHRASE FROM SECRET ENTROPY
    generate_mnemonic_from_entropy();
    
    // GENERATE SECRET MASTER SEED FROM SECRET MNEMONIC
    generate_master_seed();
    
    // GENERATE MASTER SECRET KEY AND CHAIN CODE
    generate_master_secret_key_and_chain_code();
    
    // STORE DERIVIVATION PATH
    store_deriv_path("m/44'/1729'/0'/0'", 17);
    
    // GENERATE CHILD SECRET KEY AND CHAIN CODE
    generate_child_secret_key_and_chain_code();
    
    // GENERATE PUBLIC KEY
    generate_public_key_ed25519();
    
    // GENERATE PUBLIC KEY HASH
    generate_public_key_hash();
    
}


TezioWallet::TezioWallet(uint8_t *entropy, const char path[], uint16_t path_length) {
    
}
TezioWallet::TezioWallet(const char* mnemonic[], const char path[], uint16_t path_length) {
    start_serial();
    store_mnemonic(mnemonic);
    store_deriv_path(path, path_length);
    secret_mnemonic_string_length = mnemonic_to_string(secret_mnemonic, MNEMONIC_LENGTH, secret_mnemonic_string);
    Serial.println("Deriving secret master seed using PBKDF2_HMAC_SHA512 (this may take a few moments).");
    generate_master_seed();
    // key derivation for secp256k1 and P256 are not done correctly yet. See SLIP 10
    Serial.println("Deriving private key for secp256k1 curve.");
    generate_master_secret_key_and_chain_code(SECP256K1);
    generate_child_secret_key_and_chain_code();
    print_hex_data(child_skcc, 32);
    Serial.println("Deriving private key for NIST P256 curve.");
    generate_master_secret_key_and_chain_code(NISTP256);
    generate_child_secret_key_and_chain_code();
    print_hex_data(child_skcc, 32);
    Serial.println("Deriving private key for ed25519 curve.");
    generate_master_secret_key_and_chain_code();
    generate_child_secret_key_and_chain_code();
    print_hex_data(child_skcc, 32);
    // Serial.println("Deriving public key for ed25519 curve.");
    generate_public_key_ed25519();
    // Serial.println("Calculating public key hash.");
    generate_public_key_hash();
    
}

TezioWallet::TezioWallet(bool foo, const char path[], uint16_t path_length) {
    store_mnemonic_from_serial();
    secret_mnemonic_string_length = mnemonic_to_string(secret_mnemonic, MNEMONIC_LENGTH, secret_mnemonic_string);
    generate_master_seed();
    generate_master_secret_key_and_chain_code();
    store_deriv_path(path, path_length);
    generate_child_secret_key_and_chain_code();
    generate_public_key_ed25519();
    generate_public_key_hash();
}