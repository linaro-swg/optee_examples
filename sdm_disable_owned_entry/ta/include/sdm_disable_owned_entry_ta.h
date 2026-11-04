/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TA_SDM_DISABLE_OWNED_ENTRY_H
#define TA_SDM_DISABLE_OWNED_ENTRY_H

#include <stdint.h>

#define TA_SDM_DISABLE_OWNED_ENTRY_UUID \
	{ 0xd0e00000, 0x7b2a, 0x4e5d, \
		{ 0x9c, 0x1a, 0x10, 0x0c, 0x01, 0x2e, 0xc0, 0x1d } }

#define TA_SDM_DISABLE_OWNED_ENTRY_CMD_APPLY	0

#ifndef __PTA_SDM_SVC_H
#define SDM_DEO_HOST_FLAG_NON_VOLATILE		(1U << 0)
#define SDM_DEO_HOST_FLAGS_VALID_MASK		SDM_DEO_HOST_FLAG_NON_VOLATILE
#endif

#endif /* TA_SDM_DISABLE_OWNED_ENTRY_H */
