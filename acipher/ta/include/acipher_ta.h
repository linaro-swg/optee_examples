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
 * in	params[1].memref  input
 * out	params[2].memref  output
 */
#define TA_ACIPHER_CMD_ENCRYPT		1

#endif /* __ACIPHER_TA_H */
