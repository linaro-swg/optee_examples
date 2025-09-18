/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 */

#ifndef __AES_TA_H__
#define __AES_TA_H__

/* UUID of the AES example trusted application */
#define TA_AES_UUID \
	{ 0x5dbac793, 0xf574, 0x4871, \
		{ 0x8a, 0xd3, 0x04, 0x33, 0x1e, 0xc1, 0x7f, 0x24 } }

/*
 * TA_AES_CMD_PREPARE - Allocate resources for the AES ciphering
 * param[0] (value) a: TA_AES_ALGO_xxx, b: unused
 * param[1] (value) a: key size in bytes, b: unused
 * param[2] (value) a: TA_AES_MODE_ENCODE/_DECODE, b: unused
 * param[3] unused
 */
#define TA_AES_CMD_PREPARE		0

#define TA_AES_ALGO_ECB			0
#define TA_AES_ALGO_CBC			1
#define TA_AES_ALGO_CTR			2
#define TA_AES_ALGO_CCM			3
#define TA_AES_ALGO_GCM			4

#define TA_AES_SIZE_128BIT		(128 / 8)
#define TA_AES_SIZE_256BIT		(256 / 8)

#define TA_AES_MODE_ENCODE		1
#define TA_AES_MODE_DECODE		0

/*
 * TA_AES_CMD_SET_KEY - Allocate resources for the AES ciphering
 * param[0] (memref) key data, size shall equal key length
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_AES_CMD_SET_KEY		1

/*
 * TA_AES_CMD_SET_IV - reset IV
 * param[0] (memref) initial vector, size shall equal block length
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_AES_CMD_SET_IV		2

/*
 * TA_AES_CMD_CIPHER - Cipher input buffer into output buffer
 * param[0] (memref) input buffer
 * param[1] (memref) output buffer (shall be bigger than input buffer)
 * param[2] unused
 * param[3] unused
 */
#define TA_AES_CMD_CIPHER		3

/*
 * TA_AES_CMD_AUTHENC - Encrypt and Decrypt the message
 * param[0] (memref) in: plain text for encryption, cipher text for decryption
 * param[1] (memref) out: cipher text for encryption, plain text for decryption
 * param[2] (value.a) in: 0 for decryption, any other value for encryption
 * param[3] (memref) in/out: output generated tag for encryption
 *				input authentication tag for decryption.
 */
#define TA_AES_CMD_AUTHENC		4

#endif /* __AES_TA_H */
