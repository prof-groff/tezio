/* MIT License

Copyright (c) 2024 Jeffrey R. Groff

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

#include "TezioHSM_API.h"
#include <Arduino.h>

TezioHSM_API::TezioHSM_API(uint32_t baud, const uint8_t *RWKey)
{
	memcpy(readWriteKey, RWKey, 32);
	myBaud = baud;
	Serial.begin(myBaud);
}

TezioHSM_API::~TezioHSM_API()
{
	Serial.end();
}

void TezioHSM_API::enable_signing(uint8_t key_alias, uint8_t op) {
    policy[key_alias].operation[op-1] = 1;
    return;
}

void TezioHSM_API::disable_signing(uint8_t key_alias, uint8_t op) {
    policy[key_alias].operation[op-1] = 0;
    return;
}

void TezioHSM_API::set_level_hwm(uint8_t key_alias, uint8_t baking_op, uint32_t hwmValue) {
	hwm[key_alias].level[baking_op-0x11] = hwmValue;
    return; 
}

void TezioHSM_API::set_round_hwm(uint8_t key_alias, uint8_t baking_op, uint32_t hwmValue) {
	hwm[key_alias].round[baking_op-0x11] = hwmValue;
	return;
}

uint16_t TezioHSM_API::check_key_alias()
{
	if (packet.param1 > N_KEYS) // packet.param1 is the kay alias
	{
		statusCode = INVALID_KEY_ALIAS;
		return FAIL; // invalid curve parameter, don't know which curve to return a key for
	}
	else
	{
		return PASS;
	}
}

uint16_t TezioHSM_API::validate_level_round()
{

	uint32_t current_level;
	uint32_t current_round;
	uint32_t n_fitness_bytes;

	uint8_t curve = packet.param1;
	uint8_t magicByte = packet.data[0];

	if (magicByte == 0x12 || magicByte == 0x13)
	{

		current_level = bigendian_bytes_to_uint32(&packet.data[40]);
		current_round = bigendian_bytes_to_uint32(&packet.data[44]);
	}
	else
	{
		current_level = bigendian_bytes_to_uint32(&packet.data[5]);
		n_fitness_bytes = bigendian_bytes_to_uint32(&packet.data[83]);
		current_round = bigendian_bytes_to_uint32(&packet.data[87 + n_fitness_bytes - 4]);
	}

	if ((current_level < hwm[curve].level[magicByte - 0x11]) ||
		((current_level == hwm[curve].level[magicByte - 0x11]) && (current_round <= hwm[curve].round[magicByte - 0x11])))
	{
		errorCode = LEVEL_ROUND_HIGHWATERMARK_ERROR;
		return FAIL;
	}
	else
	{
		hwm[curve].level[magicByte - 0x11] = current_level; // index by subtracting 0x11 because baking magic bytes are 0x11, 0x12, 0x13
		hwm[curve].round[magicByte - 0x11] = current_round;
		return PASS;
	}
}

uint16_t TezioHSM_API::op_get_pk()
{

	uint8_t curve = packet.param1;
	uint8_t mode = packet.param2;

	/*   curve   ECC curve to use
	0x00	NIST P256 Authentication Key (not used to sign operations)
	0x01    Ed25519
	0x02    Secp256k1
	0x03    NIST P256

	mode    pk format
	0x01    raw bytes
	0x02    compressed bytes
	0x03    base58 checksum encoded
	0x04    tezos address hash */

	// uint16_t replyLength;
	uint16_t rawKeyLength;
	uint8_t pkForm;
	Cryptochip myChip(Wire, 0x60);
	if (!myChip.begin())
	{
		errorCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
		return FAIL;
	}

	if (check_key_alias() != PASS)
	{
		return FAIL;
	}

	if (mode == NULL || mode > 4)
	{
		return 0; // don't know which form of the pk to return
	}

	switch (curve)
	{ // this is the curve
	case (ED25519):
	{
		rawKeyLength = ED_PK_SIZE;
		myChip.readSlot(ED_PK_SLOT, buffer, rawKeyLength);
		bufferLength = encode_public_key(buffer, rawKeyLength, mode, ED25519);
		break;
	}
	case (SECP256K1):
	{
		rawKeyLength = SP_PK_SIZE;
		myChip.readSlot(SP_PK_SLOT, buffer, rawKeyLength);
		bufferLength = encode_public_key(buffer, rawKeyLength, mode, SECP256K1);
		break;
	}
	case (NISTP256):
	{
		rawKeyLength = P2_PK_SIZE;
		myChip.readSlot(P2_PK_SLOT, buffer, rawKeyLength);
		bufferLength = encode_public_key(buffer, rawKeyLength, mode, NISTP256);
		break;
	}
	case (NISTP256_AUTH):
	{
		rawKeyLength = P2_PK_SIZE;
		myChip.readSlot(P2_AUTH_KEY_PK_SLOT, buffer, rawKeyLength);
		bufferLength = encode_public_key(buffer, rawKeyLength, mode, NISTP256_AUTH);
		break;
	}
	default:
	{
		return INVALID_KEY_ALIAS;
	}
	}

	myChip.end();
	return 1;
}

uint16_t TezioHSM_API::op_sign()
{

	uint8_t curve = packet.param1;
	uint8_t mode = (packet.param2 & 0x0F); // LSNibble

	// uint8_t auth = (packet.param2 & 0xF0);  // MSNibble

	uint8_t signature[64];
	uint8_t prefix[5];
	uint16_t prefixLength;

	uint8_t magicByte = packet.data[0];

	/* 	curve		Address/ECC curve to use
		0x00		NIST P256 Authentication Key
		0x01		Ed25519 (tz1)
		0x02		Secp256k1 (tz2)
		0x03		NIST P256 (tz3)

		mode		message is hashed		return signature format
		0x00		N/A						default (zeros) base58 checksum encoded
		0x01		yes						raw bytes
		0x02		yes						base58 checksum encoded
		0x03		no						raw bytes
		0x04		no						base58 checksum encoded */


	if (check_key_alias() == FAIL)
	{
		return errorCode;
	}

	if (mode > 4)
	{
		return 0; // don't know which mode to use
	}

	// set prefix for curve
	if (curve == NISTP256 || curve == NISTP256_AUTH)
	{
		prefixLength = 4;
		memcpy(prefix, TZ3_SIG, prefixLength);
	}
	else if (curve == SECP256K1)
	{
		prefixLength = 5;
		memcpy(prefix, TZ2_SIG, prefixLength);
	}
	else if (curve == ED25519)
	{
		prefixLength = 5;
		memcpy(prefix, TZ1_SIG, prefixLength);
	}
	else
	{
		return 0;
	}

	if (mode == NULL || mode == 0)
	{ // return default signature (base58 checksum of zeros)
		memset(signature, 0, 64);
	}
	else
	{
		if (packet.data == NULL || packet.dataLength == 0)
		{
			return 0; // no data to sign
		}
		// hash the message if necessary - store result in the buffer
		if (mode > 2)
		{ // message must be hashed first
			BLAKE2b blake2b;
			blake2b.reset(32);
			blake2b.update(packet.data, packet.dataLength);
			blake2b.finalize(buffer, 32);
		}
		else if (mode <= 2 && packet.dataLength == 32)
		{ // message already hashed
			memcpy(buffer, packet.data, packet.dataLength);
		}
		else
		{
			return 0; // error
		}

		// if the operation is a baking op, check watermarks
		if (magicByte == 0x11 || magicByte == 0x12 || magicByte == 0x13)
		{
			if (validate_level_round() == 0)
			{
				return 0;
			}
		}

		// sign the message, result is 64 raw bytes but set up prefix in case the base58 encoded sig is requested

		if (curve == NISTP256)
		{

			if (policy[TZ3].operation[magicByte-1] == 1)
			{ // signing allowed by policy

				Cryptochip myChip(Wire, 0x60);
				if (!myChip.begin())
				{
					return 0;
				}
				if (!myChip.ecSign(P2_SK_SLOT, buffer, signature))
				{
					return 0;
				}
				myChip.end();
			}
			else
			{
				return 0;
			}
		}

		else if (curve == NISTP256_AUTH)
		{

			if (policy[TZ3_AUTH].operation[magicByte-1] == 1)
			{

				Cryptochip myChip(Wire, 0x60);
				if (!myChip.begin())
				{
					return 0;
				}
				if (!myChip.ecSign(P2_AUTH_KEY_SLOT, buffer, signature))
				{
					return 0;
				}
				myChip.end();
			}
			else
			{
				return 0;
			}
		}

		else if (curve == SECP256K1)
		{

			if (policy[TZ2].operation[magicByte-1] == 1)
			{

				uint8_t sk[32];
				uint8_t sessionKey[32];
				uint8_t cypherText[32];
				Cryptochip myChip(Wire, 0x60);
				if (!myChip.begin())
				{
					return 0;
				}
				if (!myChip.generateSessionKey(RW_KEY_SLOT, readWriteKey, sessionKey))
				{
					return 0;
				}
				if (!myChip.encryptedRead(SP_SK_SLOT, cypherText, 32))
				{
					return 0;
				}
				if (!myChip.decryptData(cypherText, sk, 32))
				{
					return 0;
				}
				myChip.end();

				secp256k1_sign(buffer, sk, signature);
			}
			else
			{
				return 0;
			}
		}
		else if (curve == ED25519)
		{

			if (policy[TZ1].operation[magicByte-1] == 1)
			{

				uint8_t sk[32];
				uint8_t sessionKey[32];
				uint8_t cypherText[32];
				uint8_t pk[32];
				Cryptochip myChip(Wire, 0x60);
				if (!myChip.begin())
				{
					return 0;
				}
				if (!myChip.generateSessionKey(RW_KEY_SLOT, readWriteKey, sessionKey))
				{
					return 0;
				}
				if (!myChip.encryptedRead(ED_SK_SLOT, cypherText, 32))
				{
					return 0;
				}
				if (!myChip.decryptData(cypherText, sk, 32))
				{
					return 0;
				}
				if (!myChip.readSlot(ED_PK_SLOT, pk, 32))
				{
					return 0;
				}
				myChip.end();

				ed25519_sign(buffer, sk, pk, signature);
			}
			else
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}

	if (mode % 2 == 1)
	{ // odd mode, return raw bytes
		memcpy(buffer, signature, 64);
		bufferLength = 64;
		return 1;
	}
	else if (mode % 2 == 0)
	{ // even mode, return base58 checksum encoding
		// base58 checksum encode and return length of encoded signature
		bufferLength = base58_encode_prefix_checksum(prefix, prefixLength, signature, sizeof(signature), buffer) - 1;
		return 1; // subtract one so null character is not returned
	}
	else
	{
		return 0;
	}
}

uint16_t TezioHSM_API::op_verify()
{

	uint8_t curve = packet.param1;
	uint8_t mode = packet.param2;

	/* 	curve		ECC curve to use
	0x01		Ed25519
	0x02		Secp256k1
	0x03		NIST P256
	0x04		NIST P256 Authentication Key

	mode		message is hashed		signature format
	0x01		yes						raw bytes
	0x02		yes						base58 checksum encoded
	0x03		no						raw bytes
	0x04		no						base58 checksum encoded */

	if (check_key_alias() == FAIL)
	{
		return errorCode;
	}

	if (mode == NULL || mode > 4)
	{ //

		return 0;
	}
	if (packet.data == NULL || packet.dataLength == 0 || packet.dataLength < 65)
	{

		return 0; // something wrong with the data sent, must be at least 65 bytes (sig + 1byte message)
	}

	uint16_t messageLength, signatureLength, prefixLength;
	uint8_t signature[64];
	// extract the message from the data
	if (mode % 2 == 1)
	{ // odd, signature in raw bytes
		signatureLength = 64;
		messageLength = packet.dataLength - signatureLength;
		memcpy(signature, &packet.data[messageLength], signatureLength);
	}
	else if (mode % 2 == 0)
	{ // even, signature encoded
		if (packet.param3 == NULL)
		{
			return 0;
		}
		else
		{
			messageLength = packet.param3;
		}
		signatureLength = packet.dataLength - messageLength;

		char b58_sig[signatureLength + 1]; // will add a '\0' at the end because will be parsing as a character string to decode
		memset(b58_sig, '\0', sizeof(b58_sig));
		memcpy(b58_sig, &packet.data[messageLength], signatureLength); // signature comes at the end of the data

		if (curve == NISTP256 || curve == NISTP256_AUTH)
		{
			prefixLength = 4;
		}
		else
		{
			prefixLength = 5;
		}

		base58_decode_prefix_checksum(prefixLength, b58_sig, signatureLength + 1, signature);
	}
	else
	{
		return 0;
	}

	// use buffer for hash of message
	if (mode > 2)
	{ // hash the message first, store in buffer
		BLAKE2b blake2b;
		blake2b.reset(32);
		blake2b.update(&packet.data[0], messageLength);
		blake2b.finalize(buffer, 32);
	}
	else if (mode <= 2 && messageLength == 32)
	{ // message already hashed
		memcpy(buffer, &packet.data[0], messageLength);
	}
	else
	{
		return 0; // error
	}

	if (curve == NISTP256)
	{
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin())
		{
			return 0;
		}

		uint8_t pk[P2_PK_SIZE];
		myChip.readSlot(P2_PK_SLOT, pk, P2_PK_SIZE);

		if (!myChip.ecdsaVerify(buffer, signature, pk))
		{
			myChip.end();
			buffer[0] = 0;
			bufferLength = 1;
			return 0;
		}
		else
		{
			myChip.end();
			buffer[0] = 1;
			bufferLength = 1;
			return 1;
		}
	}
	else if (curve == NISTP256_AUTH)
	{ // use authentication key on P256 curve
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin())
		{
			return 0;
		}

		uint8_t pk[P2_PK_SIZE];
		myChip.readSlot(P2_AUTH_KEY_PK_SLOT, pk, P2_PK_SIZE);

		if (!myChip.ecdsaVerify(buffer, signature, pk))
		{
			myChip.end();
			buffer[0] = 0;
			bufferLength = 1;
			return 0;
		}
		else
		{
			myChip.end();
			buffer[0] = 1;
			bufferLength = 1;
			return 1;
		}
	}
	else if (curve == SECP256K1)
	{
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin())
		{
			return 0;
		}

		uint8_t pk[SP_PK_SIZE];
		myChip.readSlot(SP_PK_SLOT, pk, SP_PK_SIZE);
		myChip.end();

		if (!secp256k1_verify(buffer, pk, signature))
		{
			buffer[0] = 0;
			bufferLength = 1;
			return 0;
		}
		else
		{
			buffer[0] = 1;
			bufferLength = 1;
			return 1;
		}
	}
	else if (curve == ED25519)
	{
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin())
		{
			return 0;
		}

		uint8_t pk[ED_PK_SIZE];
		myChip.readSlot(ED_PK_SLOT, pk, ED_PK_SIZE);
		myChip.end();

		if (!ed25519_verify(buffer, pk, signature))
		{
			buffer[0] = 0;
			bufferLength = 1;
			return 0;
		}
		else
		{
			buffer[0] = 1;
			bufferLength = 1;
			return 1;
		}
	}

	return 0;
}

uint16_t TezioHSM_API::op_write_keys()
{

	uint8_t curve = packet.param1;
	uint8_t mode = packet.param2;

	/* 	curve		ECC curve to use
		0x01		Ed25519
		0x02		Secp256k1
		0x03		NIST P256
		0x00		AUTH KEY

		mode		key format
		0x01		raw bytes
		0x02		base58 checksum encoded
		0x03		base58 checksum encoded Ed25519 key w/ public key
	*/

	uint8_t sessionKey[32];
	uint8_t cypherText[32];

	/* if (check_key_alias()==FAIL) {
		return status;
	}*/

	if (mode == NULL || mode > 3)
	{
		return 0;
	}
	if (packet.data == NULL || packet.dataLength == 0 || packet.dataLength < 32)
	{
		return 0; // something is wrong with the data sent
	}

	// extract data containing key to be written
	uint8_t secretKey[32];
	uint16_t secretKeyLength = sizeof(secretKey);

	if (mode == 0x01)
	{ // key already in raw bytes
		memcpy(secretKey, &packet.data[0], packet.dataLength);
	}
	else if (mode == 0x02 || mode == 0x03)
	{										 // base58 checksum encoded
		char b58_key[packet.dataLength + 1]; // will add a '\0' at the end (null terminator to character string)
		uint8_t decodedKey[64];				 // extra 32 bytes incase it is an ed25519 key with public key appended
		memset(b58_key, '\0', sizeof(b58_key));
		memcpy(b58_key, &packet.data[0], packet.dataLength);
		base58_decode_prefix_checksum(4, b58_key, packet.dataLength + 1, decodedKey); // sk prefix length is 4 for all curves
		memcpy(secretKey, &decodedKey[0], secretKeyLength);							  // copy first 32 bytes of decodedKey into secretKey
	}
	else
	{
		return 0;
	}

	// Serial.println("secret key");
	// for (int i = 0; i < secretKeyLength; i++) {
	// 	Serial.print(secretKey[i], HEX); Serial.print(' ');
	// }
	// Serial.println();

	// get ready to perform the encrypted write
	Cryptochip myChip(Wire, 0x60);
	if (!myChip.begin())
	{
		return 0;
	}

	// generate sessionKey
	if (!myChip.generateSessionKey(RW_KEY_SLOT, readWriteKey, sessionKey))
	{
		return 0;
	}

	// use sessionKey to generate cypherText
	if (!myChip.encryptData(secretKey, cypherText, 32))
	{
		return 0;
	}

	// determine which slot is being written to
	uint16_t skSlot;
	uint16_t pkSlot;
	uint8_t publicKey[64]; // ed25519 public keys are only 32 bytes
	uint16_t publicKeyLength;

	if (curve == ED25519)
	{
		skSlot = ED_SK_SLOT;
		pkSlot = ED_PK_SLOT;
		publicKeyLength = ED_PK_SIZE;
	}
	else if (curve == SECP256K1)
	{
		skSlot = SP_SK_SLOT;
		pkSlot = SP_PK_SLOT;
		publicKeyLength = SP_PK_SIZE;
	}
	else if (curve == NISTP256)
	{
		skSlot = P2_SK_SLOT;
		pkSlot = P2_PK_SLOT;
		publicKeyLength = P2_PK_SIZE;
	}
	else
	{
		return 0;
	}

	// derive public key
	derive_public_key(secretKey, curve, publicKey);

	// compute expected MAC
	// MAC is SHA256 Hash of message = sessionkey | write opcode 0x12 | param1 0x82 | param2 address | SN[8] | SN[0:1] | Zeros(25) | Plaintext
	uint16_t messageLength = 32 + 1 + 1 + 2 + 1 + 2 + 25 + 32; // 96
	uint8_t message[messageLength];
	memcpy(&message[0], &sessionKey[0], 32);
	message[32] = 0x12;
	message[33] = 0x82;
	uint16_t address = myChip.addressForSlotOffset(skSlot, 0);
	message[34] = (uint8_t)(address);
	message[35] = (uint8_t)(address >> 8); // lsb comes first
	uint8_t sn[12];
	myChip.serialNumber(sn);
	message[36] = sn[8];
	message[37] = sn[0];
	message[38] = sn[1];
	uint8_t zeros[25];
	memset(zeros, 0, 25);
	memcpy(&message[39], &zeros[0], 25);
	memcpy(&message[64], &secretKey[0], 32);

	uint8_t mac[32];
	sha256_func_host(message, messageLength, mac);

	// try encrypted write of secret key
	if (!myChip.encryptedWrite(skSlot, cypherText, mac, 32))
	{
		return 0;
	}

	// try clear write of public key
	if (!myChip.writeSlot(pkSlot, publicKey, publicKeyLength))
	{
		return 0;
	}

	myChip.end();

	return 1;
}

uint16_t TezioHSM_API::api_crc16(uint8_t *data, uint16_t dataLength)
{
	if (data == NULL || dataLength == 0)
	{
		return 0;
	}

	uint16_t reg = 0x0000;
	uint16_t poly = 0x8005;
	uint16_t msb;

	for (uint16_t octet = 0; octet < dataLength; octet++)
	{
		for (uint16_t i = 0; i < 8; i++)
		{
			msb = reg & 0x8000;
			if (data[octet] & (0x80 >> i))
			{
				msb ^= 0x8000;
			}
			reg <<= 1;
			if (msb)
			{
				reg ^= poly;
			}
		}
		reg &= 0xFFFF;
	}
	return reg;
}

uint16_t TezioHSM_API::reset_packet()
{

	packet.opCode = 0;
	packet.param1 = 0;
	packet.param2 = 0;
	memset(packet.data, 0, sizeof(packet.data));
	packet.dataLength = 0;

	return 1;
}

uint16_t TezioHSM_API::wait_for_start_byte()
{
	while (1)
	{
		if (Serial.available() > 0)
		{
			if (Serial.read() == START_BYTE)
			{
				delay(1); // data incoming, short wait for bytes to arrive
				statusCode = START_BYTE_FOUND;
				break;
			}
		}
		delay(1); // short wait
	}
	return 1;
}

uint16_t TezioHSM_API::read_packet()
{
	packetLength = 0;
	uint16_t expectedPacketLength = 0;
	uint8_t retries = 0;

	// wait for first two bytes to arrive (length bytes)
	while (Serial.available() < 2 && retries < N_RETRIES)
	{
		retries++;
		delay(1);
	}
	if (retries == N_RETRIES)
	{
		statusCode = LENGTH_BYTES_FAILED_TO_ARRIVE;
		return 0;
	}
	else
	{
		// read the length bytes (first two bytes)
		buffer[0] = Serial.read(); // message length comes in LSB first
		buffer[1] = Serial.read();
		packetLength = 2;
		expectedPacketLength = (uint16_t)buffer[0] | (uint16_t)(buffer[1]) << 8;

		// then read in the rest of the packet
		retries = 0;
		while (packetLength < expectedPacketLength && retries < N_RETRIES)
		{
			if (Serial.available() > 0)
			{
				buffer[packetLength] = Serial.read();
				packetLength++;
			}
			else
			{
				retries++;
				delay(1);
			}
		}
		if (retries == N_RETRIES) {
			statusCode = UNEXPECTED_PACKET_LENGTH;
			return 0;
		}
		else {
			statusCode = PACKET_OF_EXPECTED_LENGTH_ARRIVED;
			return 1; 
		}

		// return packetLength;
	}
}

uint16_t TezioHSM_API::validate_packet() {
	// packet must be at least 5 bytes: length (2 bytes), opcode, two crc bytes
	if (buffer == NULL || packetLength < 5)
	{
		statusCode = INSUFFICIENT_PACKET_LENGTH;
		return 0; 
	}
	// packet crc bytes must check out
	uint16_t crc = (uint16_t)buffer[packetLength - 2] | (uint16_t)(buffer[packetLength - 1]) << 8;
	if (crc != api_crc16(buffer, packetLength - 2))
	{
		statusCode = INVALID_CRC16; 
		return 0;
	}
	// packet buffer length must match length byte
	uint16_t declaredPacketLength = (uint16_t)buffer[0] | (uint16_t)(buffer[1]) << 8;
	if (declaredPacketLength != packetLength)
	{
		statusCode = INVALID_PACKET_LENGTH;
		return 0;
	}
	statusCode = VALID_PACKET_RECEIVED;
	return 1;
}

uint16_t TezioHSM_API::parse_message()
{
	// clear data
	if (!reset_packet())
	{
		statusCode = FAILED_TO_RESET_PACKET;
		return 0;
	}
	packet.opCode = buffer[2];
	if (packetLength > 5)
	{ // param1 present
		packet.param1 = buffer[3];
	}
	if (packetLength > 6)
	{ // param2 present
		packet.param2 = buffer[4];
	}
	if (packetLength > 8)
	{ // param3 present and appears in the buffer LSB first
		packet.param3 = (uint16_t)buffer[5] | (uint16_t)(buffer[6]) << 8;
	}
	if (packetLength > 9)
	{	// data present
		// I'm keeping the following commented line of code as a reminder and a warning; do not use heap memory on microcontrollers!
		// packet.data = (uint8_t*) malloc((packetLength-9)*sizeof(uint8_t));
		memcpy(packet.data, &buffer[7], packetLength - 9);
		packet.dataLength = packetLength - 9;
	}
	statusCode = PACKET_PARSED_SUCCESSFULLY; 
	return 1;
}

uint16_t TezioHSM_API::execute_op()
{

	uint16_t replyLength = 0;
	uint16_t status;
	switch (packet.opCode)
	{
	case (GET_PK):
	{
		op_get_pk();
		break;
	}
	case (SIGN):
	{
		op_sign();
		break;
	}
	case (VERIFY):
	{
		op_verify(); // success or failure
		break;
	}
	case (WRITE_KEYS):
	{
		status = op_write_keys();
		replyLength = 1;	// reply is always one byte
		buffer[0] = status; // store result in buffer
		break;
	}
	default:
	{
		return 0;
	}
	}
	return 1;
}

uint16_t TezioHSM_API::send_reply()
{
	// shift buffer to make room for message length byte
	memmove(&buffer[2], &buffer[0], bufferLength);
	uint16_t totalBytes = bufferLength + 4;	// two length bytes and two crc bytes
	buffer[0] = (uint8_t)totalBytes & 0xFF; // LSB first
	buffer[1] = (uint8_t)(totalBytes >> 8) & 0xFF;
	uint16_t crc = api_crc16(buffer, bufferLength + 2);
	buffer[bufferLength + 2] = (uint8_t)(crc);	   // LSB
	buffer[bufferLength + 3] = (uint8_t)(crc >> 8); // MSB
	Serial.write(buffer, totalBytes);
	// send_bytes(buffer, totalBytes);
	return 1;
}

uint16_t TezioHSM_API::send_status_code()
{
	buffer[0] = statusCode;
	bufferLength = 1;
	send_reply();
	return 1;
}