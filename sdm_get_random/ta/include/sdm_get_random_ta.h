/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TA_SDM_GET_RANDOM_H
#define TA_SDM_GET_RANDOM_H

#define TA_SDM_GET_RANDOM_UUID \
	{ 0x4adb0042, 0x7b2a, 0x4e5d, \
		{ 0x9c, 0x1a, 0x10, 0x0c, 0x01, 0x2e, 0xc0, 0x1d } }

#ifndef __PTA_SDM_SVC_H
#define SDM_RNG_MIN_BYTES		4U	/* minimum: 1 word, 4-byte aligned */
#define SDM_RNG_MAX_BYTES		4080U	/* 1020 words */
#endif

#define TA_SDM_GET_RANDOM_CMD_GET	0

#endif /* TA_SDM_GET_RANDOM_H */
