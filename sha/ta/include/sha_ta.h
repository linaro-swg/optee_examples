/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef __SHA_TA_H__
#define __SHA_TA_H__

/* UUID of the SHA example trusted application */
#define TA_SHA_UUID \
	{ 0x1dc6a16b, 0x2fba, 0x4aa1, \
		{ 0x95, 0x19, 0xea, 0x8a, 0x6c, 0x8c, 0x16, 0xe5 } }

/*
 * TA_SHA_CMD_PREPARE - Allocate resources for the MAC operation
 * param[0] (value) a: TEE ID of the algo to use (TEE_ALG_xxx), b: unused
 * param[1] (value) a: key size in bytes, b: unused
 * param[2] (value) a: obj_type, b: unused
 * param[3] unused
 */
#define TA_SHA_CMD_PREPARE		0

/* SHA Algo */
#define TEE_ALG_SHA1			0x50000002
#define TEE_ALG_SHA224                  0x50000003
#define TEE_ALG_SHA256                  0x50000004
#define TEE_ALG_SHA384                  0x50000005
#define TEE_ALG_SHA512                  0x50000006
#define TEE_ALG_SHA3_224                0x50000008
#define TEE_ALG_SHA3_256                0x50000009
#define TEE_ALG_SHA3_384                0x5000000A
#define TEE_ALG_SHA3_512                0x5000000B
#define TEE_ALG_HMAC_SHA1               0x30000002
#define TEE_ALG_HMAC_SHA224             0x30000003
#define TEE_ALG_HMAC_SHA256             0x30000004
#define TEE_ALG_HMAC_SHA384             0x30000005
#define TEE_ALG_HMAC_SHA512             0x30000006
#define TEE_ALG_SHAKE128                0x50000101
#define TEE_ALG_SHAKE256                0x50000102
#define TEE_ALG_AES_CMAC                0x30000610

/* Object types */
enum ta_sha_object_type {
	TA_SHA_OBJ_TYPE_HMAC_SHA256 = 0,
	TA_SHA_OBJ_TYPE_HMAC_SHA1 = 1,
	TA_SHA_OBJ_TYPE_HMAC_SHA224 = 2,
	TA_SHA_OBJ_TYPE_HMAC_SHA384 = 3,
	TA_SHA_OBJ_TYPE_HMAC_SHA512 = 4,
	TA_SHA_OBJ_TYPE_AES = 5,
};

/*
 * TA_SHA_CMD_SET_KEY - Allocate resources for the MAC operation
 * param[0] (memref/intput) key data, size shall equal key length
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_SHA_CMD_SET_KEY		1

/*
 * TA_SHA_CMD_SET_IV - reset IV
 * param[0] (memref/input) initial vector, size shall equal block length
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_SHA_CMD_SET_IV		2

/*
 * TA_SHA_CMD_COMPUTE_MAC - Process MAC operation
 * param[0] (memref/input) message, message size
 * param[1] (memref/output) MAC buffer, buffer size
 * param[2] unused
 * param[3] unused
 */
#define TA_SHA_CMD_COMPUTE_MAC		3

/*
 * TA_SHA_CMD_COMPARE_MAC - compare MAC values
 * param[0] (memref/input) message, message size
 * param[1] (memref/input) Expected MAC data
 * param[2] unused
 * param[3] unused
 */
#define TA_SHA_CMD_COMPARE_MAC		4

/*
 * TA_SHA_CMD_COMPUTE_DIGEST - Computing the digest
 * param[0] (memref/input) message, message size
 * param[1] (memref/output) digest buffer, buffer size
 * param[2] (value/input) a:TA_ALG_SHA*, b: unused
 * param[3] unused
 */
#define TA_SHA_CMD_COMPUTE_DIGEST	5

#endif /* __SHA_TA_H */
