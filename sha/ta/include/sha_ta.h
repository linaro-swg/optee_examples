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
 * TA_SHA_CMD_PREPARE - Allocate resources for the SHA operation
 * param[0] (value) a: TA_ALGO_HMAC_xxx, b: unused
 * param[1] (value) a: key size in bytes, b: unused
 * param[2] (value) a: obj_type, b: unused
 * param[3] unused
 */
#define TA_SHA_CMD_PREPARE		0

/* SHA Algo */
#define TA_ALGO_HMAC_SHA256		0
#define TA_ALGO_HMAC_SHA1		1
#define TA_ALGO_HMAC_SHA224		2
#define TA_ALGO_HMAC_SHA384		3
#define TA_ALGO_HMAC_SHA512		4
#define TA_ALG_AES_CMAC			5

/* Object types */
#define TA_TYPE_HMAC_SHA256		0
#define TA_TYPE_HMAC_SHA1		1
#define TA_TYPE_HMAC_SHA224		2
#define TA_TYPE_HMAC_SHA384		3
#define TA_TYPE_HMAC_SHA512		4
#define TA_TYPE_AES			5

/*
 * TA_SHA_CMD_SET_KEY - Allocate resources for the SHA operation
 * param[0] (memref) key data, size shall equal key length
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_SHA_CMD_SET_KEY		1

/*
 * TA_SHA_CMD_SET_IV - reset IV
 * param[0] (memref) initial vector, size shall equal block length
 * param[1] unused
 * param[2] unused
 * param[3] unused
 */
#define TA_SHA_CMD_SET_IV		2

/*
 * TA_CMD_SHA_INIT - sha_update_ops
 * param[0] (memref) message, message size
 * param[1] (memref) MAC buffer, buffer size
 * param[2] unused
 * param[3] unused
 */
#define TA_CMD_SHA_INIT			3

/*
 * TA_CMD_SHA_CMPR - compare MAC
 * param[0] (memref) message, message size
 * param[1] (memref) MAC buffer, buffer size
 * param[2] unused
 * param[3] unused
 */
#define TA_CMD_SHA_CMPR			4

#endif /* __SHA_TA_H */
