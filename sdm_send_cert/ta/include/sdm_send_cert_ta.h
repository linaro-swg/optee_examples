/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TA_SDM_SEND_CERT_H
#define TA_SDM_SEND_CERT_H

#include <stdint.h>

#define TA_SDM_SEND_CERT_UUID \
	{ 0x5ec71000, 0x7b2a, 0x4e5d, \
		{ 0x9c, 0x1a, 0x10, 0x0c, 0x01, 0x2e, 0xc0, 0x1d } }

#define TA_SDM_SEND_CERT_CMD_SEND	0

/* -------------------------------------------------------------------------
 * SDM / VAB certificate limits, re-exported from the PTA header
 * (pta_sdm_svc.h) so NW callers do not need to pull in OP-TEE OS
 * internals.  Suppressed when pta_sdm_svc.h is also visible (TA build)
 * via its include guard.
 * -------------------------------------------------------------------------
 */
#ifndef __PTA_SDM_SVC_H
#define SDM_CERT_MAX_SIZE		4096U
#endif

/* Common header constants (apply to every cert_type) */
#define SDM_CERT_MAGIC_NUM		0x25D04E7FU
#define VAB_CERT_HEADER_SIZE		0x50U	/* keychain starts at 0x50 */
#define VAB_CERT_MIN_SIZE		0x14U	/* hdr + 1 word at 0x10 */

/* -------------------------------------------------------------------------
 * Certificate type identifiers - the value stored at offset 0x0C.
 *
 * Values 0x01..0x0F come from the per-type table in the doc.  The two
 * Beta types use ASCII-encoded discriminators (4 bytes BE).
 * -------------------------------------------------------------------------
 */
#define SDM_CERT_TYPE_ENGINEERING		0x01U
#define SDM_CERT_TYPE_USER_AES_ROOT_KEY		0x02U
#define SDM_CERT_TYPE_RMA			0x03U
#define SDM_CERT_TYPE_DEBUG			0x04U
#define SDM_CERT_TYPE_COUNTER_SET		0x05U
#define SDM_CERT_TYPE_VAB_SRC			0x06U
#define SDM_CERT_TYPE_PR_OWNER_PUBKEY		0x07U
#define SDM_CERT_TYPE_KILL_PERMIT		0x08U
#define SDM_CERT_TYPE_OWNER_PUBKEY_LATE		0x09U
#define SDM_CERT_TYPE_DECOMMISSION		0x0AU
#define SDM_CERT_TYPE_CANCEL_SDOS_SRK		0x0BU
#define SDM_CERT_TYPE_PROVISION_SDOS_SRK	0x0CU
#define SDM_CERT_TYPE_CANCEL_USER_AES		0x0DU
#define SDM_CERT_TYPE_OWNERSHIP_XFER_FROM	0x0EU
#define SDM_CERT_TYPE_OWNERSHIP_XFER_TO		0x0FU
#define SDM_CERT_TYPE_BETA_PREVIEW		0x42444350U	/* "BDCP" */
#define SDM_CERT_TYPE_BETA_LOCAL		0x4244434CU	/* "BDCL" */

/* -------------------------------------------------------------------------
 * Type-specific magic words at offset 0x10 (a.k.a. "2nd magic").
 *
 * Not every cert_type has one — the table below records "None" for
 * 0x05 (SDM 1.5 removed it), 0x09 (no 2nd magic by design), and the
 * Beta cert types.  For 0x06 / 0x07 the 2nd magic differs between SDM
 * 1.2 (FM) and SDM 1.5 (SM); see the validation table below.
 * -------------------------------------------------------------------------
 */
#define SDM_CERT_TYPE_ENGR_RMA_DBG_MAGIC	0x97566593U	/* 0x01, 0x03, 0x04 */
#define SDM_CERT_TYPE_AES_ROOT_MAGIC		0xD0850CAAU	/* 0x02 */
/* 0x05 COUNTER_SET_CERT: no 2nd magic (SDM 1.5 removed it) */
#define SDM_CERT_TYPE_VAB_SRC_15_MAGIC		0x52619311U	/* 0x06, SM */
/* 0x06 VAB_SRC_CERT, FM: 2nd magic == SDM_CERT_MAGIC_NUM (legacy) */
#define SDM_CERT_TYPE_PR_OWNER_PK_MAGIC		0x88171010U	/* 0x07, SM */
/* 0x07, FM: no 2nd magic */
#define SDM_CERT_TYPE_KILL_PERMIT_MAGIC		0x4B696C6CU	/* 0x08 "Kill" */
/* 0x09 Owner Pubkey Late Prov: no 2nd magic */
#define SDM_CERT_TYPE_DECOMMISSION_MAGIC	0x6465636FU	/* 0x0A "deco" */
#define SDM_CERT_TYPE_CANCEL_SDOS_MAGIC		0x62977477U	/* 0x0B */
#define SDM_CERT_TYPE_PROV_SDOS_MAGIC		0x13099605U	/* 0x0C */
#define SDM_CERT_TYPE_CANCEL_AES_MAGIC		0x87072118U	/* 0x0D */
#define SDM_CERT_TYPE_OWN_XFER_FROM_MAGIC	0x71776691U	/* 0x0E */
#define SDM_CERT_TYPE_OWN_XFER_TO_MAGIC		0x38142061U	/* 0x0F */
/* Beta types: no 2nd magic */

/* -------------------------------------------------------------------------
 * Common header (offsets 0x00..0x0F) - identical to the first four
 * words of struct fcs_hps_vab_certificate_header in ATF.  Used as a
 * generic discriminator for any certificate type.
 * -------------------------------------------------------------------------
 */
struct sdm_cert_hdr {
	uint32_t cert_magic_num;	/* 0x00 : SDM_CERT_MAGIC_NUM */
	uint32_t cert_data_sz;		/* 0x04 : "data" size; excludes keychain */
	uint32_t cert_ver;		/* 0x08 : per-type, see table */
	uint32_t cert_type;		/* 0x0C : SDM_CERT_TYPE_* */
};

/* -------------------------------------------------------------------------
 * Type-specific structures.
 *
 * Each struct starts with the common header so the host can simply
 * cast its certificate buffer and read the discriminator.  Fields
 * beyond offset 0x10 are documented per-type in
 * docs/security_mailbox_certificate_types.md; only the bytes that the
 * TA actively checks are named here.  The remainder (signing keychain,
 * type-private payload) is opaque to the TA - the SDM enforces it.
 * -------------------------------------------------------------------------
 */

/* 0x01 Engineering / 0x03 RMA / 0x04 Debug -- shared format */
struct sdm_cert_engr_rma_dbg {
	struct sdm_cert_hdr hdr;
	uint32_t type_magic;		/* 0x10 : SDM_CERT_TYPE_ENGR_RMA_DBG_MAGIC */
	uint32_t rsvd_14[8];		/* 0x14..0x33 */
	uint32_t flags;			/* 0x34 : ENABLE_RMA / CANCEL_ALL_RMA /
					 *        Engineering / *_DEBUG / *_TAP */
};

/* 0x02 User AES Root Key */
struct sdm_cert_aes_root_key {
	struct sdm_cert_hdr hdr;
	uint32_t type_magic;		/* 0x10 : SDM_CERT_TYPE_AES_ROOT_MAGIC */
	uint32_t storage_type;		/* 0x14 b7:0 : 0=BBRAM 1=eFuse 2=off-chip */
	uint32_t wrap_select;		/* 0x18 b7:0 : 0=NoWrap 1=Internal
					 *             2=IID_PUF 3=Intel_PUF */
};

/* 0x05 COUNTER_SET_CERT -- no 2nd magic (SDM 1.5) */
struct sdm_cert_counter_set {
	struct sdm_cert_hdr hdr;
	uint8_t  counter_type;		/* 0x10 b7:0 : 0..6 or 255 */
	uint8_t  rsvd_11[3];
	uint32_t counter_value;		/* 0x14 : -1 = pre-auth (types 1..6) */
};

/* 0x06 VAB_SRC_CERT (HPS image authentication) */
struct sdm_cert_vab_src {
	struct sdm_cert_hdr hdr;
	uint32_t vab_cert_magic_num;	/* 0x10 : SDM_CERT_MAGIC_NUM (FM) or
					 *        SDM_CERT_TYPE_VAB_SRC_15_MAGIC (SM) */
	uint32_t flags;			/* 0x14 */
	uint8_t  rsvd0_1[8];		/* 0x18..0x1F */
	uint8_t  fcs_sha384[48];	/* 0x20..0x4F */
	/* 0x50 : measurement attributes (SDM 1.5) + keychain */
};

/* 0x07 Secondary (PR) Owner PUBKEY Auth */
struct sdm_cert_pr_owner_pubkey {
	struct sdm_cert_hdr hdr;
	uint32_t type_magic;		/* 0x10 : SDM_CERT_TYPE_PR_OWNER_PK_MAGIC (SM)
					 *        ; 0 / unused (FM) */
	uint32_t flags;			/* 0x14 b15:0 cancel-slot, b16 PR root,
					 *        b17 ext-auth root, ... */
};

/* 0x08 Kill Permit */
struct sdm_cert_kill_permit {
	struct sdm_cert_hdr hdr;
	uint32_t type_magic;		/* 0x10 : SDM_CERT_TYPE_KILL_PERMIT_MAGIC */
};

/* 0x09 Owner Pubkey Late Provisioning */
struct sdm_cert_owner_pubkey_late {
	struct sdm_cert_hdr hdr;
	uint8_t  rsvd_10[16];		/* 0x10..0x1F */
	uint8_t  root_hash[48];		/* 0x20..0x4F : one new root hash */
};

/* 0x0A Decommission */
struct sdm_cert_decommission {
	struct sdm_cert_hdr hdr;
	uint32_t type_magic;		/* 0x10 : SDM_CERT_TYPE_DECOMMISSION_MAGIC */
};

/* 0x0B Cancel Old SDOS Service Root Key */
struct sdm_cert_cancel_sdos_srk {
	struct sdm_cert_hdr hdr;
	uint32_t type_magic;		/* 0x10 : SDM_CERT_TYPE_CANCEL_SDOS_MAGIC */
	uint32_t flags;			/* 0x14 b29:30 FIPS mode selector */
};

/* 0x0C Provision SDOS Service Root Key */
struct sdm_cert_provision_sdos_srk {
	struct sdm_cert_hdr hdr;
	uint32_t type_magic;		/* 0x10 : SDM_CERT_TYPE_PROV_SDOS_MAGIC */
	uint32_t flags;			/* 0x14 b3:0 entropy words, b29:30 FIPS
					 *        b30 SDOS test (FM), b31 virtual */
};

/* 0x0D Cancel Old User AES Root Key */
struct sdm_cert_cancel_user_aes {
	struct sdm_cert_hdr hdr;
	uint32_t type_magic;		/* 0x10 : SDM_CERT_TYPE_CANCEL_AES_MAGIC */
	uint32_t flags;			/* 0x14 b0 : 0=cancel one, 1=cancel all */
};

/* 0x0E Ownership Transfer (From) */
struct sdm_cert_ownership_xfer_from {
	struct sdm_cert_hdr hdr;
	uint32_t type_magic;		/* 0x10 : SDM_CERT_TYPE_OWN_XFER_FROM_MAGIC */
	uint32_t flags;			/* 0x14 */
};

/* 0x0F Ownership Transfer (To) */
struct sdm_cert_ownership_xfer_to {
	struct sdm_cert_hdr hdr;
	uint32_t type_magic;		/* 0x10 : SDM_CERT_TYPE_OWN_XFER_TO_MAGIC */
	uint32_t flags;			/* 0x14 */
};

/* Beta Preview (0x42444350) / Local (0x4244434C) -- no 2nd magic */
struct sdm_cert_beta {
	struct sdm_cert_hdr hdr;
	uint32_t beta_cycle;		/* 0x10 : Beta cycle counter value */
};

#endif /* TA_SDM_SEND_CERT_H */
