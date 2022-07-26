#include "TezioWallet_API.h"


TezioWallet_API::TezioWallet_API(uint32_t baud, const uint8_t *RWKey, bool debug) {
	debugFlag = debug;
	if(debugFlag) {
		// don't go into listening mode
		start_serial(baud);
		memcpy(readWriteKey, RWKey, 32); 
	}
	else {
	start_serial(baud);
	memcpy(readWriteKey, RWKey, 32); 
	uint16_t packetLength, replyLength;
  	while (1) {
		wait_for_start_byte(START_BYTE);
		packetLength = read_packet();
      	if (validate_packet(packetLength) == 0) {
        	// fail, send error code and proceed after short wait
        	send_error(INVALID_PACKET);
        	delay(1);
      	}
      	else if (parse_message(packetLength) == 0) {
        	// fail, send error code and proceed after short wait
        	send_error(PARSE_ERROR);
        	delay(1);
		}
      	else if ((replyLength = execute_op()) == 0) {
        	// failed to execute op command
        	send_error(OP_ERROR);
        	delay(1);
      	}
      	else {
        	send_reply(replyLength);
      	}
	}
	}
}

uint16_t TezioWallet_API::op_get_pk() {
	
	uint8_t curve = packet.param1;
	uint8_t mode = packet.param2;
	
	/*   curve   ECC curve to use
    0x01    Ed25519
    0x02    Secp256k1
    0x03    NIST P256
  
    mode    pk format
    0x01    raw bytes
    0x02    compressed bytes
    0x03    base58 checksum encoded
    0x04    tezos address hash */
	
	
	uint16_t replyLength;
	uint16_t rawKeyLength; 
	uint8_t pkForm;
	Cryptochip myChip(Wire, 0x60);
	if (!myChip.begin()) {
		return 0; 
	}
	
	if (curve == NULL || curve > 3) {
		return 0; // invalid curve parameter, don't know which curve to return a key for
	}
	

	if (mode == NULL || mode > 4) {
		return 0; // don't know which form of the pk to return
	}


 
  	switch(curve) { // this is the curve
    case(ED25519):
			{
				rawKeyLength = ED_PK_SIZE;
				myChip.readSlot(ED_PK_SLOT, buffer, rawKeyLength);
				replyLength = encode_public_key(buffer, rawKeyLength, mode, ED25519);
				break;
			}
    case(SECP256K1): 
			{
				rawKeyLength = SP_PK_SIZE;
				myChip.readSlot(SP_PK_SLOT, buffer, rawKeyLength);
				replyLength = encode_public_key(buffer, rawKeyLength, mode, SECP256K1);
				break;
			}
    case(NISTP256):
			{
				rawKeyLength = P2_PK_SIZE;
				myChip.readSlot(P2_PK_SLOT, buffer, rawKeyLength);
				replyLength = encode_public_key(buffer, rawKeyLength, mode, NISTP256);
				break;
			}
    default:
			{
				return 0;
			}
  }
	
	return replyLength;
 	
}

uint16_t TezioWallet_API::op_sign() {
	
	uint8_t curve = packet.param1;
	uint8_t mode = packet.param2; 
	
	/* 	curve		ECC curve to use
		0x01		Ed25519
		0x02		Secp256k1
		0x03		NIST P256
	
		mode		message is hashed		signature format
		0x01		yes						raw bytes
		0x02		yes						base58 checksum encoded
		0x03		no						raw bytes
		0x04		no						base58 checksum encoded */
	
	if (curve == NULL || curve > 3) { // for variables NULL is 0
		return 0; // don't know which curve to use
	}
	if (mode == NULL || mode > 4) {
		return 0; // don't know which mode to use
	}
	if (packet.data == NULL || packet.dataLength == 0) {
		return 0; // no data to sign
	}
	
	
	// hash the message if necessary - store result in the buffer
	if (mode > 2) { // message must be hashed first
		BLAKE2b blake2b; 
    	blake2b.reset(32);
    	blake2b.update(packet.data, packet.dataLength);
    	blake2b.finalize(buffer, 32);
	}
	else if (mode <= 2 && packet.dataLength == 32) {// message already hashed
		memcpy(buffer, packet.data, packet.dataLength);
	}
	else {
		return 0; // error
	}
	
	uint8_t signature[64];
	uint8_t prefix[5];
	uint16_t prefixLength;
	
	// sign the message, result is 64 raw bytes but set up prefix in case the base58 encoded sig is requested
	if (curve == NISTP256) {
		
		prefixLength = 4;
		memcpy(prefix, TZ3_SIG, prefixLength);
		
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin()) {
			return 0; 
		}
		if (!myChip.ecSign(P2_SK_SLOT, buffer, signature)) {
			return 0;
		}
		myChip.end();
	}
	else if (curve == SECP256K1) {
		
		prefixLength = 5;
		memcpy(prefix, TZ2_SIG, prefixLength);
		
		uint8_t sk[32];
		uint8_t sessionKey[32];
		uint8_t cypherText[32];
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin()) {
			return 0; 
		}
		if (!myChip.generateSessionKey(RW_KEY_SLOT, readWriteKey, sessionKey)){
			return 0;
		}
		if (!myChip.encryptedRead(SP_SK_SLOT, cypherText, 32)) {
			return 0;
		}
		if (!myChip.decryptData(cypherText, sk, 32)){
			return 0;
		}
		myChip.end();
		
		secp256k1_sign(buffer, sk, signature);
		
	}
	else if (curve == ED25519) {
		
		prefixLength = 5;
		memcpy(prefix, TZ1_SIG, prefixLength);
		
		uint8_t sk[32];
		uint8_t sessionKey[32];
		uint8_t cypherText[32];
		uint8_t pk[32];
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin()) {
			return 0;
		}
		if (!myChip.generateSessionKey(RW_KEY_SLOT, readWriteKey, sessionKey)){
			return 0;
		}
		if (!myChip.encryptedRead(ED_SK_SLOT, cypherText, 32)) {
			return 0;
		}
		if (!myChip.decryptData(cypherText, sk, 32)){
			return 0;
		}
		if (!myChip.readSlot(ED_PK_SLOT, pk, 32)) {
			return 0;
		}
		myChip.end();

		
		ed25519_sign(buffer, sk, pk, signature);
		
	}
	else {
		return 0;
	}
	
	
	if (mode%2 == 1) { // odd mode, return raw bytes
		memcpy(buffer, signature, 64);
		return 64;
	}
	else if (mode%2 == 0) { // even mode, return base58 checksum encoding
		// base58 checksum encode and return length of encoded signature
		return base58_encode_prefix_checksum(prefix, prefixLength, signature, sizeof(signature), buffer); 
	
	}
	else {
		return 0;
	}
	
	
}

uint16_t TezioWallet_API::op_verify() {
	
	uint8_t curve = packet.param1;
	uint8_t mode = packet.param2;
	
		/* 	curve		ECC curve to use
		0x01		Ed25519
		0x02		Secp256k1
		0x03		NIST P256
	
		mode		message is hashed		signature format
		0x01		yes						raw bytes
		0x02		yes						base58 checksum encoded
		0x03		no						raw bytes
		0x04		no						base58 checksum encoded */
	
	
	if (curve == NULL || curve > 3) {
		
		return 0;
	}
	if (mode == NULL || mode > 4) { // 
		
		return 0;
	}
	if (packet.data == NULL || packet.dataLength == 0 || packet.dataLength < 65) {
		
		return 0; // something wrong with the data sent, must be at least 65 bytes (sig + 1byte message)
	}
	
	uint16_t messageLength, signatureLength, prefixLength;
	uint8_t signature[64];
	// extract the message from the data
	if (mode%2 == 1) { // odd, signature in raw bytes
		signatureLength = 64;
		messageLength = packet.dataLength - signatureLength;
		memcpy(signature, &packet.data[messageLength], signatureLength);
	}
	else if (mode%2 == 0) { // even, signature encoded
		if (packet.param3 == NULL) {
			return 0;
		}
		else {
			messageLength = packet.param3;
		}
		signatureLength = packet.dataLength - messageLength;
		
		char b58_sig[signatureLength + 1]; // will add a '\0' at the end because will be parsing as a character string to decode
		memset(b58_sig, '\0', sizeof(b58_sig));
		memcpy(b58_sig, &packet.data[messageLength], signatureLength); // signature comes at the end of the data
		
		if (curve == NISTP256) {
			prefixLength = 4;
		}
		else {
			prefixLength = 5;
		}
		
		base58_decode_prefix_checksum(prefixLength, b58_sig, signatureLength + 1, signature);
	}
	else {
		return 0;
	}
		
	
	// use buffer for hash of message
	if (mode > 2) { // hash the message first, store in buffer
		BLAKE2b blake2b; 
    	blake2b.reset(32);
    	blake2b.update(&packet.data[0], messageLength);
    	blake2b.finalize(buffer, 32);
	}
	else if (mode <=2 && messageLength == 32) {// message already hashed
		memcpy(buffer, &packet.data[0], messageLength); 
	}
	else {
		return 0; // error
	}
	
	
	if (curve == NISTP256) {
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin()) {
			return 0; 
		}
		
		uint8_t pk[P2_PK_SIZE];
		myChip.readSlot(P2_PK_SLOT, pk, P2_PK_SIZE);
		
		if (!myChip.ecdsaVerify(buffer, signature, pk)){
			myChip.end();
			return 0;
		}
		else {
			myChip.end();
			return 1;
		}	
	}
	else if (curve == SECP256K1) {
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin()) {
			return 0; 
		}
		
		uint8_t pk[SP_PK_SIZE];
		myChip.readSlot(SP_PK_SLOT, pk, SP_PK_SIZE);
		myChip.end();
		
		if (!secp256k1_verify(buffer, pk, signature)) {	
			return 0;
		}
		else {
			return 1;
		}
	}
	else if (curve == ED25519) {
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin()) {
			return 0; 
		}
		
		uint8_t pk[ED_PK_SIZE];
		myChip.readSlot(ED_PK_SLOT, pk, ED_PK_SIZE);
		myChip.end();
		
		if (!ed25519_verify(buffer, pk, signature)) {
			return 0;
		}
		else {
			return 1;
		}

	}

    return 0;
}


uint16_t TezioWallet_API::api_crc16(uint8_t *data, uint16_t dataLength) {
	if (data == NULL || dataLength == 0) {
		return 0;
  	}

  	uint16_t reg = 0x0000;
	uint16_t poly = 0x8005;
  	uint16_t msb;
	
	for (uint16_t octet = 0; octet < dataLength; octet++) {
    	for (uint16_t i = 0; i < 8; i++) {
      		msb = reg & 0x8000;
      		if (data[octet] & (0x80 >> i)) {
        		msb ^= 0x8000;
      		}
      		reg <<= 1; 
      		if (msb) {
        		reg ^= poly;
      		}
    	}
    	reg &= 0xFFFF;
  	}
  	return reg;
}

uint16_t TezioWallet_API::reset_packet() {
	
	packet.opCode = NULL;
	packet.param1 = NULL;
	packet.param2 = NULL;
	packet.data = NULL;
	packet.dataLength = NULL;
	
	return 1;
}

uint16_t TezioWallet_API::wait_for_start_byte(uint8_t startByte) {
	while (1) {
		while(Serial.available() == 0) {
			delay(1); // nothing in buffer, short wait to throtle
		}
		if (Serial.read() == startByte) {
			delay(1); // data incoming, short wait for bytes to arrive
			break;
		}
	}
	return 1;
}

uint16_t TezioWallet_API::read_packet() {
	uint16_t packetLength = 0;
	while (Serial.available() > 0) {
		buffer[packetLength] = Serial.read();
		packetLength++;
	}
	return packetLength;
}

uint16_t TezioWallet_API::validate_packet(uint16_t packetLength) {
	// packet must be at least 4 bytes: length, opcode, two crc bytes
	if (buffer == NULL || packetLength < 4) {
    	return 0;
  	}
	// packet crc bytes must check out
  	uint16_t crc = buffer[packetLength - 2] | (uint16_t)(buffer[packetLength -1]) << 8;
  	if (crc != api_crc16(buffer, packetLength - 2)) {
    	return 0;
  	}
	// packet buffer length must match length byte
  	if (buffer[0] != packetLength) {
    	return 0; 
  }
  return 1;
}

uint16_t TezioWallet_API::parse_message(uint16_t packetLength) {
	// clear data
	if(!reset_packet()) {
		return 0; 
	}
	packet.opCode = buffer[1];
	if (packetLength > 4) {  // param1 present
		packet.param1 = buffer[2];
	}
	if (packetLength > 5) { // param2 present
		packet.param2 = buffer[3];
	}
	if (packetLength > 7) { // param3 present and appears in the buffer LSB first
		packet.param3 = (uint16_t)buffer[4] | (uint16_t)(buffer[5]) << 8 ;
	}
	if (packetLength > 8) { // data present
		packet.data = (uint8_t*) malloc((packetLength-8)*sizeof(uint8_t));
    	memcpy(packet.data, &buffer[6], packetLength - 8);
    	packet.dataLength = packetLength - 8;
	}
	return 1;
}

uint16_t TezioWallet_API::execute_op() {
	
	uint16_t replyLength = 0;
	uint16_t valid;
	switch(packet.opCode) {
		case(GET_PK):
			{
				replyLength = op_get_pk();
				break;
			}
		case(SIGN):
			{
				replyLength = op_sign();
				break;
			}
		case(VERIFY):
			{
				valid = op_verify();
				replyLength = 1; // reply is always on byte
				buffer[0] = valid; // store result in buffer
				break;
			}
		default:
			{
				return 0;
			}
				
	}
	return replyLength;
}

uint16_t TezioWallet_API::send_reply(uint16_t replyLength) {
	// shift buffer to make room for message length byte
	memmove(&buffer[1], &buffer[0], replyLength);
	buffer[0] = replyLength + 3; // length byte and two crc bytes
	uint16_t crc = api_crc16(buffer, replyLength+1);
	buffer[replyLength + 1] = (uint8_t)(crc); // LSB
	buffer[replyLength + 2] = (uint8_t)(crc >> 8); // MSB
	send_bytes(buffer, replyLength+3);
	return 1;
}

uint16_t TezioWallet_API::send_error(uint8_t errorCode) {
	buffer[0] = errorCode;
	send_reply(1);
	return 1;
}