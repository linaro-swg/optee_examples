// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef __ACIPHER_TA_H__
#define __ACIPHER_TA_H__

/* UUID of the acipher example trusted application */
#define TA_ACIPHER_UUID \
	{ 0xa734eed9, 0xd6a1, 0x4244, { \
		0xaa, 0x50, 0x7c, 0x99, 0x71, 0x9e, 0x7b, 0x7b } }

/*
 * in	params[0].value.a key size
 */
#define TA_ACIPHER_CMD_GEN_KEY		0

/*
 * in	params[0].memref  Input data to cipher
 * out	params[1].memref  Ciphered output data
 * in   params[2].value.a  Mode: 0 for decryption, any other value for
 * encryption
 * in   params[3].value.a  Algorithm (TA_ALG_*)
 */
#define TA_ACIPHER_CMD_ENCRYPT_DECRYPT	1

#define TA_ALG_PKCS1_V1_5		0x60000130
#define TA_ALG_OAEP_MGF1_SHA1		0x60210230
#define TA_ALG_OAEP_MGF1_SHA224		0x60310230
#define TA_ALG_OAEP_MGF1_SHA256		0x60410230
#define TA_ALG_OAEP_MGF1_SHA384		0x60510230
#define TA_ALG_OAEP_MGF1_SHA512		0x60610230

#endif /* __ACIPHER_TA_H */
