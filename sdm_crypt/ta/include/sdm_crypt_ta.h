/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TA_SDM_CRYPT_H
#define TA_SDM_CRYPT_H

#include <stdint.h>

#define TA_SDM_CRYPT_UUID \
	{ 0x5d050000, 0x7b2a, 0x4e5d, \
		{ 0x9c, 0x1a, 0x10, 0x0c, 0x01, 0x2e, 0xc0, 0x1d } }

#define TA_SDM_CRYPT_DIR_DECRYPT	0
#define TA_SDM_CRYPT_DIR_ENCRYPT	1

#define TA_SDM_CRYPT_CMD_RUN		0

/* ---------------------------------------------------------------------------
 * SDOS layout constants & sdos_hdr structure
 *
 * Re-exported from the SDM PTA (pta_sdm_svc.h) so that NW callers of this
 * TA do not need to pull in OP-TEE OS internal headers.  When this header
 * is consumed inside the TA (which also includes pta_sdm_svc.h from the
 * TA dev kit) the duplicated definitions are suppressed via the PTA
 * header's include guard.  Keep these values in sync with the PTA.
 * ---------------------------------------------------------------------------
 */

#ifndef __PTA_SDM_SVC_H

#define SDOS_HDR_SIZE			40
#define SDOS_HMAC_SIZE			48
#define SDOS_ENCRYPT_IN_MAGIC		0xACBDBDEDU
#define SDOS_ENCRYPT_OUT_MAGIC		0x53424212U
#define SDOS_HDR_PAD_MAGIC		0x01020304U

/* Zero when n is already a multiple of 32, else (32 - n%32). Range [0..31]. */
#define SDOS_PAD_LEN(n)			(((n) % 32) ? (32 - ((n) % 32)) : 0)

/* data_len (= plaintext + padding) must lie in this range. */
#define SDOS_MIN_DATA_LEN		32U
#define SDOS_MAX_DATA_LEN		(32U * 1024U - 96U)	/* 32,672 bytes */

#define SDOS_FLAGS(asoi, srk_index, pad_len) \
	(((uint32_t)(asoi) << 16) | \
	 ((uint32_t)(srk_index) << 8) | \
	 (uint32_t)(pad_len))

/*
 * SDOS 40-byte header - placed at offset 0 of the encrypt/decrypt buffer.
 * Fields are little-endian 32-bit words; total size is exactly SDOS_HDR_SIZE.
 */
struct sdos_hdr {
	uint32_t magic;		/* SDOS_ENCRYPT_IN_MAGIC or SDOS_ENCRYPT_OUT_MAGIC */
	uint32_t data_len;	/* plaintext_len + pad_len  (multiple of 32) */
	uint32_t flags;		/* SDOS_FLAGS(asoi, srk_index, pad_len) */
	uint32_t owner_id[2];	/* 8-byte owner ID, little-endian */
	uint32_t hdr_pad;	/* must be SDOS_HDR_PAD_MAGIC (0x01020304) */
	uint32_t iv[4];		/* {0} on encrypt input, filled by SDM on output */
};

#endif /* __PTA_SDM_SVC_H */

/* Always-available helper - extracts pad_len from sdos_hdr.flags */
#define SDOS_FLAGS_PAD_LEN(flags)	((uint32_t)(flags) & 0xFFU)

#endif /* TA_SDM_CRYPT_H */
