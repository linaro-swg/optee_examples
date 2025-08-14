/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef __ECDSA_TA_H__
#define __ECDSA_TA_H__

/* UUID of the ECDSA example trusted application */

#define TA_ECDSA_UUID \
	{ 0x1945e8e7, 0x0278, 0x4bfb, \
		{ 0xbb, 0x99, 0xaf, 0x10, 0x80, 0xb2, 0xa9, 0x34 } }

#define TA_ECDSA_CMD_COMPUTE_DIGEST		0
#define TA_ECDSA_GEN_KEY			1
#define TA_ECDSA_SIGN_VERIFY_DIGEST		2

#define TEE_ALG_ECDSA_SHA1	0x70001042
#define TEE_ALG_ECDSA_SHA224	0x70002042
#define TEE_ALG_ECDSA_SHA256	0x70003042
#define TEE_ALG_ECDSA_SHA384	0x70004042
#define TEE_ALG_ECDSA_SHA512    0x70005042

#endif
