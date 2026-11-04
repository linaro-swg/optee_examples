/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TA_SDM_PROG_PUBKEY_H
#define TA_SDM_PROG_PUBKEY_H

#include <stdint.h>

#define TA_SDM_PROG_PUBKEY_UUID \
	{ 0xec384000, 0x7b2a, 0x4e5d, \
		{ 0x9c, 0x1a, 0x10, 0x0c, 0x01, 0x2e, 0xc0, 0x1d } }

#define TA_SDM_PROG_PUBKEY_CMD_SET	0

#ifndef __PTA_SDM_SVC_H
#define SDM_PUBKEY_HASH_SIZE_SHA384	48U
#define SDM_PUBKEY_HASH_SIZE_SHA256	32U
#define SDM_PUBKEY_HOST_FLAG_NON_VOLATILE	(1U << 0)
#define SDM_PUBKEY_HOST_FLAGS_VALID_MASK	SDM_PUBKEY_HOST_FLAG_NON_VOLATILE
#define SDM_PUBKEY_MAX_HASHES_PER_CALL	5U
/* param[3].a values, so NW callers can tell a finalized burn from a stuck one */
#define SDM_PHASE2_STATUS_SUCCESS	0U
#define SDM_PHASE2_STATUS_NOP		1U
#define SDM_PHASE2_STATUS_SKIPPED	2U
#define SDM_PHASE2_STATUS_FAILED	3U
#else
#ifndef SDM_PUBKEY_HASH_SIZE_SHA256
#define SDM_PUBKEY_HASH_SIZE_SHA256	32U
#endif
#ifndef SDM_PUBKEY_MAX_HASHES_PER_CALL
#define SDM_PUBKEY_MAX_HASHES_PER_CALL	5U
#endif
#endif

#endif /* TA_SDM_PROG_PUBKEY_H */
