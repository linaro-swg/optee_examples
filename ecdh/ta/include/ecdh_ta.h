/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef __ECDH_TA_H__
#define __ECDH_TA_H__

/* UUID of the ECDH example trusted application */

#define TA_ECDH_UUID \
	{ 0x50c82425, 0x94da, 0x4072, \
		{ 0xa3, 0xe0, 0x58, 0xef, 0x06, 0x37, 0x67, 0xc0 } }

#define TA_ECDH_CMD_DERIVE_SELFTEST		0

#define TA_ECDH_ECC_CURVE_NIST_P192		0
#define TA_ECDH_ECC_CURVE_NIST_P224		1
#define TA_ECDH_ECC_CURVE_NIST_P256		2
#define TA_ECDH_ECC_CURVE_NIST_P384		3

#define ECDH_MAX_BITS   521
#define ECDH_MAX_BYTES  ((ECDH_MAX_BITS + 7) / 8)
#define ECDH_BUF_BYTES  (ECDH_MAX_BYTES + 14)

#endif
