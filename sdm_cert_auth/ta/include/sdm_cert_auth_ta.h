/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TA_SDM_CERT_AUTH_H
#define TA_SDM_CERT_AUTH_H

#include <stdint.h>

#define TA_SDM_CERT_AUTH_UUID \
	{ 0x5ec70000, 0x7b2a, 0x4e5d, \
		{ 0x9c, 0x1a, 0x10, 0x0c, 0x01, 0x2e, 0xc0, 0x1d } }

#define TA_SDM_CERT_AUTH_CMD_SEND	0

#ifndef __PTA_SDM_SVC_H
#define SDM_CERT_MAX_SIZE		4096U
#endif

/* VAB cert layout constants - these are NOT defined in pta_sdm_svc.h */
#define SDM_CERT_MAGIC_NUM		0x25D04E7FU
#define VAB_CERT_HEADER_SIZE		0x50U	/* keychain starts at 0x50 */
#define VAB_CERT_MIN_SIZE		VAB_CERT_HEADER_SIZE

struct sdm_cert_hdr {
	uint32_t cert_magic_num;	/* offset 0x00, must == SDM_CERT_MAGIC_NUM */
	uint32_t cert_data_sz;		/* offset 0x04, size of "data" portion */
	uint32_t cert_ver;		/* offset 0x08 */
	uint32_t cert_type;		/* offset 0x0C */
	/* struct fcs_hps_vab_certificate_data d at offset 0x10: */
	uint32_t vab_cert_magic_num;	/* offset 0x10, must == SDM_CERT_MAGIC_NUM */
	uint32_t flags;			/* offset 0x14 */
	uint8_t  rsvd0_1[8];		/* offset 0x18..0x1F */
	uint8_t  fcs_sha384[48];	/* offset 0x20..0x4F */
	/* offset 0x50: keychain (RSA pubkey + signature, variable length) */
};

#endif /* TA_SDM_CERT_AUTH_H */
