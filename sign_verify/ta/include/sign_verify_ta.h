/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef __SIGN_VERIFY_TA_H__
#define __SIGN_VERIFY_TA_H__

/* UUID of the AES example trusted application */
#define TA_SIGN_VERIFY_UUID \
	{ 0xf066f150, 0x42af, 0x404f, \
		{ 0xae, 0x32, 0xc8, 0xe6, 0xcd, 0x11, 0x7e, 0x70 } }

#define TA_RSA_SIGN_CMD_SIGN_VERIFY	0

#define TA_ALG_PKCS1_PSS_MGF1_SHA1	0
#define TA_ALG_PKCS1_PSS_MGF1_SHA224	1
#define TA_ALG_PKCS1_PSS_MGF1_SHA256	2
#define TA_ALG_PKCS1_PSS_MGF1_SHA384	3
#define TA_ALG_PKCS1_PSS_MGF1_SHA512	4

#define TA_ALG_PKCS1_V1_5_SHA1		5
#define TA_ALG_PKCS1_V1_5_SHA224	6
#define TA_ALG_PKCS1_V1_5_SHA256	7
#define TA_ALG_PKCS1_V1_5_SHA384	8
#define TA_ALG_PKCS1_V1_5_SHA512	9

#define MAX_SIG_SIZE			512

#endif
