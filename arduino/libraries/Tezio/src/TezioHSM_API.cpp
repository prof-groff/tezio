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

	// want to set all policy[KEY].hsm_ops[HSM_OP] to 1 (enabled)
	memset(policy[TZ1].hsm_ops, 1, N_HSM_OPS);
	memset(policy[TZ2].hsm_ops, 1, N_HSM_OPS);
	memset(policy[TZ3].hsm_ops, 1, N_HSM_OPS);
	memset(policy[TZ3_AUTH].hsm_ops, 1, N_HSM_OPS);

}

TezioHSM_API::~TezioHSM_API()
{
	Serial.end();
}

void TezioHSM_API::enable_tezos_op(uint8_t key_alias, uint8_t op)
{
	policy[key_alias].tezos_ops[op - 1] = 1;
	return;
}

void TezioHSM_API::disable_hsm_op(uint8_t key_alias, uint8_t op)
{
	policy[key_alias].hsm_ops[op - 1] = 0;
	return;
}

void TezioHSM_API::set_level_hwm(uint8_t key_alias, uint8_t baking_op, uint32_t hwmValue)
{
	hwm[key_alias].level[baking_op - 0x11] = hwmValue;
	return;
}

void TezioHSM_API::set_round_hwm(uint8_t key_alias, uint8_t baking_op, uint32_t hwmValue)
{
	hwm[key_alias].round[baking_op - 0x11] = hwmValue;
	return;
}

uint16_t TezioHSM_API::validate_param_1_2(uint8_t param, uint8_t minVal, uint8_t maxVal)
{
	if (param >= minVal && param <= maxVal) // parameter in valid range
	{
		return PASS;
	}
	else
	{
		return FAIL;
	}
}

uint16_t TezioHSM_API::validate_data(uint8_t *data, uint16_t dataLength, uint16_t minLength, uint16_t maxLength)
{
	if (data == NULL)
	{
		return FAIL;
	}
	else if (dataLength >= minLength && dataLength <= maxLength)
	{
		return PASS;
	}
	else
	{
		return FAIL;
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
	/*  packet.param1 is curve/address/slot alias
		0x00	NIST P256 Authentication Key (not used to sign operations)
		0x01    Ed25519
		0x02    Secp256k1
		0x03    NIST P256

		packet.param2 is public key format to return
		0x01    raw bytes
		0x02    compressed bytes
		0x03    base58 checksum encoded
		0x04    tezos address/public key hash */

	if (validate_param_1_2(packet.param1, 0x00, 0x03) != PASS)
	{
		statusCode = PARAM_1_INVALID;
		return FAIL; // don't know which curve to use
	}

	// check to see if HSM op is disabled for this key
	if (policy[packet.param1].hsm_ops[GET_PK-1]== 0) {
		statusCode = HSM_OPERATION_FORBIDDEN_BY_POLICY;
		return FAIL;
	}

	if (validate_param_1_2(packet.param2, 0x01, 0x04) != PASS)
	{
		statusCode = PARAM_2_INVALID;
		return FAIL; // don't know which key format to return
	}

	// initialize coms with cryptographic co-processor/HSM
	Cryptochip myChip(Wire, 0x60);
	if (!myChip.begin())
	{
		statusCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
		return FAIL;
	}

	switch (packet.param1) // this is curve/address/slot alias
	{
	case (ED25519):
	{
		myChip.readSlot(ED_PK_SLOT, buffer, ED_PK_SIZE);
		bufferLength = encode_public_key(buffer, ED_PK_SIZE, packet.param2, ED25519);
		break;
	}
	case (SECP256K1):
	{
		myChip.readSlot(SP_PK_SLOT, buffer, SP_PK_SIZE);
		bufferLength = encode_public_key(buffer, SP_PK_SIZE, packet.param2, SECP256K1);
		break;
	}
	case (NISTP256):
	{
		myChip.readSlot(P2_PK_SLOT, buffer, P2_PK_SIZE);
		bufferLength = encode_public_key(buffer, P2_PK_SIZE, packet.param2, NISTP256);
		break;
	}
	case (NISTP256_AUTH):
	{
		myChip.readSlot(P2_AUTH_KEY_PK_SLOT, buffer, P2_PK_SIZE);
		bufferLength = encode_public_key(buffer, P2_PK_SIZE, packet.param2, NISTP256_AUTH);
		break;
	}
	default:
	{
		return FAIL;
	}
	}

	myChip.end();
	return SUCCESS;
}

uint16_t TezioHSM_API::op_sign()
{
	/* 	packet.param1 is curve/address/slot alias
		0x00		NIST P256 Authentication Key
		0x01		Ed25519 (tz1)
		0x02		Secp256k1 (tz2)
		0x03		NIST P256 (tz3)

		packet.param2 is message/signature mode
					message is hashed		return signature format
		0x00		N/A						default (zeros) base58 checksum encoded
		0x01		yes						raw bytes
		0x02		yes						base58 checksum encoded
		0x03		no						raw bytes
		0x04		no						base58 checksum encoded */

	if (validate_param_1_2(packet.param1, 0x00, 0x03) != PASS)
	{
		statusCode = PARAM_1_INVALID;
		return FAIL;
	}

	// check to see if HSM op is disabled for this key
	if (policy[packet.param1].hsm_ops[SIGN-1]== 0) {
		statusCode = HSM_OPERATION_FORBIDDEN_BY_POLICY;
		return FAIL;
	}


	if (validate_param_1_2(packet.param2, 0x00, 0x04) != PASS)
	{
		statusCode = PARAM_2_INVALID;
		return FAIL;
	}

	uint16_t prefixLength;
	uint8_t prefix[5];
	uint8_t signature[64];
	uint8_t magicByte = packet.data[0];

	if (packet.param2 == 0) // return default signature (zeros or base58 checksum of zeros)
	{
		memset(signature, 0, 64);
		prefixLength = 3;
		memcpy(prefix, DEF_SIG, prefixLength);
	}
	else
	{
		if (validate_data(packet.data, packet.dataLength, 1, MAX_DATA_LENGTH) != PASS)
		{
			statusCode = DATA_OR_DATA_LENGTH_INVALID;
			return FAIL;
		}
		if (packet.param2 > 2) // hash the message if necessary - store result in the buffer
		{
			BLAKE2b blake2b;
			blake2b.reset(32);
			blake2b.update(packet.data, packet.dataLength);
			blake2b.finalize(buffer, 32);
		}
		else if (packet.param2 <= 2 && packet.dataLength == 32)
		{
			memcpy(buffer, packet.data, packet.dataLength); // message already hashed
		}
		else
		{
			statusCode = MESSAGE_HASH_STATUS_INDETERMINANT;
			return FAIL; // error
		}

		// if the operation is a baking op, check watermarks
		if (magicByte == 0x11 || magicByte == 0x12 || magicByte == 0x13)
		{
			if (validate_level_round() != PASS)
			{
				errorCode = LEVEL_ROUND_HIGHWATERMARK_ERROR;
				return FAIL;
			}
		}

		// check if requested signiture is for an allowed operation
		// then sign the message.
		// the result is 64 raw bytes but base58 encoded sig may be requested
		if (packet.param1 == NISTP256)
		{
			if (policy[TZ3].tezos_ops[magicByte - 1] != ALLOWED)
			{
				statusCode = SIGNING_OPERATION_FORBIDDEN_BY_POLICY;
				return FAIL;
			}
			else
			{ // signing allowed by policy

				// initialize coms with cryptographic co-processor/HSM
				Cryptochip myChip(Wire, 0x60);
				if (!myChip.begin())
				{
					statusCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
					return FAIL;
				}
				if (!myChip.ecSign(P2_SK_SLOT, buffer, signature))
				{
					statusCode = HSM_FAILED_TO_SIGN;
					return FAIL;
				}
				myChip.end();
			}
		}

		else if (packet.param1 == NISTP256_AUTH)
		{
			if (policy[TZ3_AUTH].tezos_ops[magicByte - 1] != ALLOWED)
			{
				statusCode = SIGNING_OPERATION_FORBIDDEN_BY_POLICY;
				return FAIL;
			}
			else
			{
				Cryptochip myChip(Wire, 0x60);
				if (!myChip.begin())
				{
					statusCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
					return FAIL;
				}
				if (!myChip.ecSign(P2_AUTH_KEY_SLOT, buffer, signature))
				{
					statusCode = HSM_FAILED_TO_SIGN;
					return FAIL;
				}
				myChip.end();
			}
		}

		else if (packet.param1 == SECP256K1)
		{
			if (policy[TZ2].tezos_ops[magicByte - 1] != ALLOWED)
			{
				statusCode = SIGNING_OPERATION_FORBIDDEN_BY_POLICY;
				return FAIL;
			}
			else
			{
				uint8_t sk[32];
				uint8_t sessionKey[32];
				uint8_t cypherText[32];
				Cryptochip myChip(Wire, 0x60);
				if (!myChip.begin())
				{
					statusCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
					return FAIL;
				}
				if (!myChip.generateSessionKey(RW_KEY_SLOT, readWriteKey, sessionKey))
				{
					statusCode = FAILED_TO_GENERATE_SESSION_KEY;
					return FAIL;
				}
				if (!myChip.encryptedRead(SP_SK_SLOT, cypherText, 32))
				{
					statusCode = ENCRYPTED_READ_FAILED;
					return FAIL;
				}
				if (!myChip.decryptData(cypherText, sk, 32))
				{
					statusCode = FAILED_TO_DECRYPT_DATA;
					return FAIL;
				}
				myChip.end();

				secp256k1_sign(buffer, sk, signature); // signed in software
				// overwrite secret key for security
				memset(sk, 0, 32);
			}
		}
		else if (packet.param1 == ED25519)
		{
			if (policy[TZ1].tezos_ops[magicByte - 1] != ALLOWED)
			{
				statusCode = SIGNING_OPERATION_FORBIDDEN_BY_POLICY;
				return FAIL;
			}
			else
			{
				uint8_t sk[32];
				uint8_t sessionKey[32];
				uint8_t cypherText[32];
				uint8_t pk[32];
				Cryptochip myChip(Wire, 0x60);
				if (!myChip.begin())
				{
					statusCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
					return FAIL;
				}
				if (!myChip.generateSessionKey(RW_KEY_SLOT, readWriteKey, sessionKey))
				{
					statusCode = FAILED_TO_GENERATE_SESSION_KEY;
					return FAIL;
				}
				if (!myChip.encryptedRead(ED_SK_SLOT, cypherText, 32))
				{
					statusCode = ENCRYPTED_READ_FAILED;
					return FAIL;
				}
				if (!myChip.decryptData(cypherText, sk, 32))
				{
					statusCode = FAILED_TO_DECRYPT_DATA;
					return FAIL;
				}
				if (!myChip.readSlot(ED_PK_SLOT, pk, 32))
				{
					statusCode = FAILED_TO_READ_PK_SLOT;
					return FAIL;
				}
				myChip.end();

				ed25519_sign(buffer, sk, pk, signature);
				memset(sk, 0, 32); // overwrite sk for security
			}
		}
		else
		{
			statusCode = INVALID_KEY_ALIAS;
			return FAIL;
		}
	}

	// set prefix for curve
	if (packet.param1 == NISTP256 || packet.param1 == NISTP256_AUTH)
	{
		prefixLength = 4;
		memcpy(prefix, TZ3_SIG, P2_SIG_PREFIX_LENGTH);
	}
	else if (packet.param1 == SECP256K1)
	{
		prefixLength = 5;
		memcpy(prefix, TZ2_SIG, SP_SIG_PREFIX_LENGTH);
	}
	else if (packet.param1 == ED25519)
	{
		prefixLength = 5;
		memcpy(prefix, TZ1_SIG, ED_SIG_PREFIX_LENGTH);
	}
	else
	{
		statusCode = INVALID_KEY_ALIAS;
		return FAIL;
	}

	if (packet.param2 % 2 == 1) // param2 is odd, return raw bytes
	{
		memcpy(buffer, signature, 64);
		bufferLength = 64;
		return SUCCESS;
	}
	else if (packet.param2 % 2 == 0) // param2 is even, return base58 checksum encoded signature
	{
		// base58 checksum encode and return length of encoded signature
		bufferLength = base58_encode_prefix_checksum(prefix, prefixLength, signature, sizeof(signature), buffer) - 1;
		return SUCCESS; // subtract one so null character is not returned
	}
	else
	{
		statusCode = PARAM_2_INVALID;
		return FAIL;
	}
}

uint16_t TezioHSM_API::op_verify()
{
	/* 	packet.param1 is curve/address/slot alias
	0x00		NIST P256 Authentication Key
	0x01		Ed25519 (tz1)
	0x02		Secp256k1 (tz2)
	0x03		NIST P256 (tz3)

	packet.param2 is message/signature format
				message is hashed		signature format
	0x01		yes						raw bytes
	0x02		yes						base58 checksum encoded
	0x03		no						raw bytes
	0x04		no						base58 checksum encoded */

	if (validate_param_1_2(packet.param1, 0x00, 0x03) != PASS)
	{
		statusCode = PARAM_1_INVALID;
		return FAIL;
	}
	// check to see if HSM op is disabled for this key
	if (policy[packet.param1].hsm_ops[VERIFY-1]== 0) {
		statusCode = HSM_OPERATION_FORBIDDEN_BY_POLICY;
		return FAIL;
	}
	if (validate_param_1_2(packet.param2, 0x01, 0x04) != PASS)
	{
		statusCode = PARAM_2_INVALID;
		return FAIL;
	}
	if (validate_data(packet.data, packet.dataLength, 65, MAX_DATA_LENGTH) != PASS)
	{
		statusCode = DATA_OR_DATA_LENGTH_INVALID;
		return FAIL; // something wrong with the data sent, must be at least 65 bytes (sig + 1byte message)
	}

	uint16_t messageLength, signatureLength, prefixLength;
	uint8_t signature[64];
	// extract the message from the data
	if (packet.param2 % 2 == 1)
	{ // odd, signature in raw bytes
		signatureLength = 64;
		messageLength = packet.dataLength - signatureLength;
		memcpy(signature, &packet.data[messageLength], signatureLength);
	}
	else if (packet.param2 % 2 == 0)
	{ // even, signature encoded
		if (packet.param3 == 0)
		{
			statusCode = PARAM_3_INVALID;
			return FAIL;
		}
		else
		{
			messageLength = packet.param3;
		}
		signatureLength = packet.dataLength - messageLength;

		char b58_sig[signatureLength + 1]; // will add a '\0' at the end because will be parsing as a character string to decode
		memset(b58_sig, '\0', sizeof(b58_sig));
		memcpy(b58_sig, &packet.data[messageLength], signatureLength); // signature comes at the end of the data

		if (packet.param1 == NISTP256 || packet.param1 == NISTP256_AUTH)
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
		statusCode = PARAM_2_INVALID;
		return FAIL;
	}

	// use buffer for hash of message
	if (packet.param2 > 2)
	{ // hash the message first, store in buffer
		BLAKE2b blake2b;
		blake2b.reset(32);
		blake2b.update(&packet.data[0], messageLength);
		blake2b.finalize(buffer, 32);
	}
	else if (packet.param2 <= 2 && messageLength == 32)
	{ // message already hashed
		memcpy(buffer, &packet.data[0], messageLength);
	}
	else
	{
		statusCode = PARAM_2_INVALID;
		return FAIL;
	}

	if (packet.param1 == NISTP256)
	{
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin())
		{
			statusCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
			return FAIL;
		}

		uint8_t pk[P2_PK_SIZE];
		if (!myChip.readSlot(P2_PK_SLOT, pk, P2_PK_SIZE))
		{
			statusCode = FAILED_TO_READ_PK_SLOT;
			return FAIL;
		}

		if (!myChip.ecdsaVerify(buffer, signature, pk))
		{
			myChip.end();
			buffer[0] = 0;
			bufferLength = 1;
			return SUCCESS; // the signature is invalid but the check was successful
		}
		else
		{
			myChip.end();
			buffer[0] = 1;
			bufferLength = 1;
			return SUCCESS;
		}
	}
	else if (packet.param1 == NISTP256_AUTH)
	{ // use authentication key on P256 curve
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin())
		{
			statusCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
			return FAIL;
		}

		uint8_t pk[P2_PK_SIZE];
		if (!myChip.readSlot(P2_AUTH_KEY_PK_SLOT, pk, P2_PK_SIZE))
		{
			statusCode = FAILED_TO_READ_PK_SLOT;
			return FAIL;
		}

		if (!myChip.ecdsaVerify(buffer, signature, pk))
		{
			myChip.end();
			buffer[0] = 0;
			bufferLength = 1;
			return SUCCESS; // signature invalid but check succeeded
		}
		else
		{
			myChip.end();
			buffer[0] = 1;
			bufferLength = 1;
			return SUCCESS;
		}
	}
	else if (packet.param1 == SECP256K1)
	{
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin())
		{
			statusCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
			return FAIL;
		}

		uint8_t pk[SP_PK_SIZE];
		if (!myChip.readSlot(SP_PK_SLOT, pk, SP_PK_SIZE))
		{
			statusCode = FAILED_TO_READ_PK_SLOT;
			return FAIL;
		}
		myChip.end();
		if (!secp256k1_verify(buffer, pk, signature))
		{
			buffer[0] = 0;
			bufferLength = 1;
			return SUCCESS; // signature invalid but check succeeded
		}
		else
		{
			buffer[0] = 1;
			bufferLength = 1;
			return SUCCESS;
		}
	}
	else if (packet.param1 == ED25519)
	{
		Cryptochip myChip(Wire, 0x60);
		if (!myChip.begin())
		{
			statusCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
			return FAIL;
		}

		uint8_t pk[ED_PK_SIZE];
		if (!myChip.readSlot(ED_PK_SLOT, pk, ED_PK_SIZE))
		{
			statusCode = FAILED_TO_READ_PK_SLOT;
			return FAIL;
		}
		myChip.end();

		if (!ed25519_verify(buffer, pk, signature))
		{
			buffer[0] = 0;
			bufferLength = 1;
			return SUCCESS; // signature invalid but check succeeded
		}
		else
		{
			buffer[0] = 1;
			bufferLength = 1;
			return SUCCESS;
		}
	}
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
		if (retries == N_RETRIES)
		{
			statusCode = UNEXPECTED_PACKET_LENGTH;
			return 0;
		}
		else
		{
			statusCode = PACKET_OF_EXPECTED_LENGTH_ARRIVED;
			return 1;
		}

		// return packetLength;
	}
}

uint16_t TezioHSM_API::validate_packet()
{
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
	{ // data present
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
	uint16_t result_of_op;
	switch (packet.opCode)
	{
	case (GET_PK):
	{
		result_of_op = op_get_pk();
		break;
	}
	case (SIGN):
	{
		result_of_op = op_sign();
		break;
	}
	case (VERIFY):
	{
		result_of_op = op_verify(); // success or failure
		break;
	}
	default:
	{
		statusCode = INVALID_OPERATION_CODE;
		return FAIL;
	}
	}
	if (result_of_op != SUCCESS) {
		return FAIL;
	}
	else {
		return SUCCESS;
	}
}

uint16_t TezioHSM_API::send_reply()
{
	// shift buffer to make room for message length byte
	memmove(&buffer[2], &buffer[0], bufferLength);
	uint16_t totalBytes = bufferLength + 4; // two length bytes and two crc bytes
	buffer[0] = (uint8_t)totalBytes & 0xFF; // LSB first
	buffer[1] = (uint8_t)(totalBytes >> 8) & 0xFF;
	uint16_t crc = api_crc16(buffer, bufferLength + 2);
	buffer[bufferLength + 2] = (uint8_t)(crc);		// LSB
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

// EXPERIMENTAL
/* 

uint16_t TezioHSM_API::op_write_keys()
{
	// 	packet.param1 is key/curve/alias
					key/curve/alias
	//	0x00		NIST P256 AUTH KEY
	//	0x01		Ed25519
	//	0x02		Secp256k1
	//	0x03		NIST P256

	//	mode		key format
	//	0x01		raw bytes
	//	0x02		base58 checksum encoded
	//	0x03		base58 checksum encoded Ed25519 key w/ public key

	if (validate_param_1_2(packet.param1, 0x00, 0x03) != PASS)
	{
		statusCode = PARAM_1_INVALID;
		return FAIL;
	}
	// check to see if HSM op is disabled for this key
	if (policy[packet.param1].hsm_ops[WRITE_KEYS-1]== 0) {
		statusCode = HSM_OPERATION_FORBIDDEN_BY_POLICY;
		return FAIL;
	}
	if (validate_param_1_2(packet.param2, 0x01, 0x03) != PASS)
	{
		statusCode = PARAM_2_INVALID;
		return FAIL;
	}

	uint8_t curve = packet.param1;
	uint8_t mode = packet.param2;

	uint8_t sessionKey[32];
	uint8_t cypherText[32];

	// extract data containing key to be written
	uint8_t secretKey[32];
	uint16_t secretKeyLength = 32;
	uint8_t publicKey[64]; // ed25519 public keys are only 32 bytes
	uint16_t publicKeyLength;

	if (validate_data(packet.data, packet.dataLength, 32, MAX_DATA_LENGTH) != SUCCESS) {
		statusCode = DATA_OR_DATA_LENGTH_INVALID;
		return FAIL;
	}

	// determine which slot is being written to
	uint16_t skSlot;
	uint16_t pkSlot;

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
	else if (curve == NISTP256_AUTH) 
	{
		skSlot = P2_AUTH_KEY_SLOT;
		pkSlot = P2_AUTH_KEY_PK_SLOT;
		publicKeyLength = P2_PK_SIZE;
	}
	else
	{
		statusCode = INVALID_KEY_ALIAS;
		return FAIL;
	}

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
		base58_decode_prefix_checksum(N_SK_PREFIX_BYTES, b58_key, packet.dataLength + 1, decodedKey); // sk prefix length is 4 for all curves
		memcpy(secretKey, &decodedKey[0], secretKeyLength); // copy first 32 bytes of decodedKey into secretKey
		if (mode == 0x03) { // public key is also encoded
			memcpy(publicKey, &decodedKey[secretKeyLength], publicKeyLength);
		}
		else 
		{
			// derive public key
			derive_public_key(secretKey, curve, publicKey);
		}
	}
	else
	{
		statusCode = PARAM_2_INVALID;
		return FAIL;
	}

	// get ready to perform the encrypted write
	Cryptochip myChip(Wire, 0x60);
	if (!myChip.begin())
	{
		statusCode = CRYPTOCHIP_FAILED_TO_INITIALIZE;
		return FAIL;
	}

	// generate sessionKey
	if (!myChip.generateSessionKey(RW_KEY_SLOT, readWriteKey, sessionKey))
	{
		statusCode = FAILED_TO_GENERATE_SESSION_KEY;
		return FAIL;
	}

	// use sessionKey to generate cypherText
	if (!myChip.encryptData(secretKey, cypherText, 32))
	{
		statusCode = FAILED_TO_ENCRYPT_DATA;
		return FAIL;
	}	

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
		statusCode = FAILED_ENCRYPTED_WRITE;
		return FAIL;
	}

	// try clear write of public key
	if (!myChip.writeSlot(pkSlot, publicKey, publicKeyLength))
	{
		statusCode = FAILED_CLEAR_WRITE;
		return FAIL;
	}

	myChip.end();

	return SUCCESS;
}

*/