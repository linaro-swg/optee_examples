/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef __BASE_SHA_TA_H__
#define __BASE_SHA_TA_H__

/* UUID of the AES example trusted application */

#define TA_BASE_SHA_UUID \
	{ 0xabb97be3, 0xf56b, 0x46d5, \
		{ 0xb7, 0xfd, 0x70, 0xf2, 0x8c, 0xfe, 0xd9, 0x92 } }

#define CMD_COMPUTE_DIGEST	0

#define TA_ALG_SHA1		0
#define TA_ALG_SHA224		1
#define TA_ALG_SHA256		2
#define TA_ALG_SHA384		3
#define TA_ALG_SHA512		4
#define TA_ALG_SHA3_224		5
#define TA_ALG_SHA3_256		6
#define TA_ALG_SHA3_384		7
#define TA_ALG_SHA3_512		8
#define TA_ALG_SHAKE128		9
#define TA_ALG_SHAKE256		10

#endif
