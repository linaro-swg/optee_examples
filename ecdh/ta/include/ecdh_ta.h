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

/*
 * TA_ECDH_CMD_DERIVE_SELFTEST - Test EC keys generation and ECDH derivation
 *
 * in params[0].value.a EC curve ID (one of TA_ECDH_ECC_CURVE_*)
 * out params[3].memref Generated shared secret key from ECDH
 *
 * Return TEE_SUCCESS upon success.
 * Return TEE_ERROR_SHORT_BUFFER is output buffer is too short in which case
 * size is provided output in param[3]memref.size)
 * Return another compliant TEE_Result error code in case of failure.
 */
#define TA_ECDH_CMD_DERIVE_SELFTEST		0

#define TA_ECDH_ECC_CURVE_NIST_P192		0
#define TA_ECDH_ECC_CURVE_NIST_P224		1
#define TA_ECDH_ECC_CURVE_NIST_P256		2
#define TA_ECDH_ECC_CURVE_NIST_P384		3

#endif
