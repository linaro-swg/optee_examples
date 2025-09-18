/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 */

#ifndef __RANDOM_TA_H__
#define __RANDOM_TA_H__

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_RANDOM_UUID \
	{ 0xb6c53aba, 0x9669, 0x4668, \
		{ 0xa7, 0xf2, 0x20, 0x56, 0x29, 0xd0, 0x0f, 0x86} }

/* The function ID implemented in this TA */
#define TA_RANDOM_CMD_GENERATE		0

#endif /* __RANDOM_TA_H__ */
