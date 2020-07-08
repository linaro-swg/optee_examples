// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Elias von Däniken
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "base64.h"

char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int dec_base64(char c)
{
	for (size_t i = 0; i < strlen(table); i++)
		if (table[i] == c)
			return i;
	return -1;
}

int base64_encode(unsigned char *plain, size_t plain_len, char *enc)
{
	char byte[3];
	int nr[4];
	int blocks = plain_len / 3;

	for (size_t i = 0; i < blocks; i++) {
		// Prepare the bytes
		byte[0] = plain[i * 3];
		byte[1] = plain[i * 3 + 1];
		byte[2] = plain[i * 3 + 2];

		// calculate the number of the table
		nr[0] = byte[0] >> 2;
		nr[1] = ((byte[0] & 0b00000011) << 4) | (byte[1] >> 4);
		nr[2] = ((byte[1] & 0b00001111) << 2) | (byte[2] >> 6);
		nr[3] = byte[2] & 0b00111111;

		//write the encoded bytes to the output buffer
		enc[i * 4]     = table[nr[0]];
		enc[i * 4 + 1] = table[nr[1]];
		enc[i * 4 + 2] = table[nr[2]];
		enc[i * 4 + 3] = table[nr[3]];
	}

	// padding for one byte over
	if (plain_len - blocks*3 == 1) {
		byte[0] = plain[plain_len - 1];
		nr[0] = byte[0] >> 2;
		nr[1] = (byte[0] & 0b00000011) << 4;
		enc[blocks * 4]     = table[nr[0]];
		enc[blocks * 4 + 1] = table[nr[1]];
		enc[blocks * 4 + 2] = '=';
		enc[blocks * 4 + 3] = '=';
		}

	// padding for two byte over
	if (plain_len - blocks*3 == 2) {
		byte[0] = plain[plain_len - 2];
		byte[1] = plain[plain_len - 1];
		nr[0] = byte[0] >> 2;
		nr[1] = ((byte[0] & 0b00000011) << 4) | (byte[1] >> 4);
		nr[2] = ((byte[1] & 0b00001111) << 2);
		enc[blocks * 4]     = table[nr[0]];
		enc[blocks * 4 + 1] = table[nr[1]];
		enc[blocks * 4 + 2] = table[nr[2]];
		enc[blocks * 4 + 3] = '=';
	}
	return 0;
}

int base64_decode(char *enc, size_t enc_len, unsigned char *dec)
{
	if (enc_len % 4 != 0)
		return 1;

	char symbol[4];
	int blocks = enc_len / 4;

	for (size_t i = 0; i < blocks; i++) {
		// Prepare the symbols
		symbol[0] = dec_base64(enc[i * 4]);
		symbol[1] = dec_base64(enc[i * 4 + 1]);
		symbol[2] = dec_base64(enc[i * 4 + 2]);
		symbol[3] = dec_base64(enc[i * 4 + 3]);

		// translate the symbols to binary data
		dec[i * 3] = ((symbol[0] & 0b00111111) << 2) | ((symbol[1] & 0b00110000) >> 4);
		if (!(symbol[2]  == -1))
			dec[i * 3 + 1] = ((symbol[1] & 0b00001111) << 4) | ((symbol[2] & 0b00111100) >> 2);
		if (!(symbol[3]  == -1))
			dec[i * 3 + 2] = ((symbol[2] & 0b00000011) << 6) | ((symbol[3] & 0b00111111) >> 0);
	}
	return 0;
}

int plain_len_to_enc(size_t plain_len)
{
	if (plain_len % 3)
		return 4 * ((plain_len / 3) + 1);
	return 4 * (plain_len / 3);
}

int enc_len_to_plain(size_t enc_len)
{
	if (enc_len % 4)
		return 0;
	return 3 * (enc_len / 4);
}
