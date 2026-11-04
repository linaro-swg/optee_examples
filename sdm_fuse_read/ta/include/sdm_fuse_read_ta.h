/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TA_SDM_FUSE_READ_H
#define TA_SDM_FUSE_READ_H

#include <stdint.h>

#define TA_SDM_FUSE_READ_UUID \
	{ 0x0f05e000, 0x7b2a, 0x4e5d, \
		{ 0x9c, 0x1a, 0x10, 0x0c, 0x01, 0x2e, 0xc0, 0x1d } }

#define TA_SDM_FUSE_READ_CMD_GET	0

#ifndef __PTA_SDM_SVC_H
#define SDM_USER_FUSE_COUNT		16U
#define SDM_USER_FUSE_SIZE		(SDM_USER_FUSE_COUNT * 4U)	/* 64 */
#endif

#endif /* TA_SDM_FUSE_READ_H */
