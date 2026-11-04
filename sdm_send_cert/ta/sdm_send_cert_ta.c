// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_sdm_svc.h>
#include <sdm_send_cert_ta.h>

struct cert_sess_ctx {
	TEE_TASessionHandle pta_sess;
};


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("sdm_send_cert TA: create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("sdm_send_cert TA: destroy");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void **sess_ctx)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	const TEE_UUID pta_uuid = PTA_SDM_SVC_UUID;
	struct cert_sess_ctx *ctx = NULL;
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	uint32_t pta_pt = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = TEE_Malloc(sizeof(*ctx), TEE_MALLOC_FILL_ZERO);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_OpenTASession(&pta_uuid, TEE_TIMEOUT_INFINITE,
				TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE),
				pta_params, &ctx->pta_sess, &pta_origin);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenTASession(PTA_SDM_SVC) failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		TEE_Free(ctx);
		return res;
	}

	pta_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				 TEE_PARAM_TYPE_NONE,
				 TEE_PARAM_TYPE_NONE,
				 TEE_PARAM_TYPE_NONE);
	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_GET_VERSION, pta_pt,
				  pta_params, &pta_origin);
	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_GET_VERSION failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		TEE_CloseTASession(ctx->pta_sess);
		TEE_Free(ctx);
		return res;
	}

	if (pta_params[0].value.a < PTA_SDM_SVC_API_VERSION) {
		EMSG("PTA API version %u too old (need %u)",
		     pta_params[0].value.a, PTA_SDM_SVC_API_VERSION);
		TEE_CloseTASession(ctx->pta_sess);
		TEE_Free(ctx);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	IMSG("sdm_send_cert TA: session opened, PTA API v%u",
	     pta_params[0].value.a);
	*sess_ctx = ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct cert_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return;

	TEE_CloseTASession(ctx->pta_sess);
	TEE_Free(ctx);
	IMSG("sdm_send_cert TA: session closed");
}


/*
 * 0x01 Engineering / 0x03 RMA / 0x04 Debug -- shared format.
 * cert_ver: 0 (SDM 1.2) or 1 (SDM 1.5).  2nd magic mandatory.
 */
static TEE_Result check_engr_rma_dbg(const void *cert, size_t cert_size,
				     const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_engr_rma_dbg *c =
		(const struct sdm_cert_engr_rma_dbg *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("engr/rma/dbg: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver > 1) {
		EMSG("engr/rma/dbg: bad cert_ver %u (allowed: 0, 1)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (c->type_magic != SDM_CERT_TYPE_ENGR_RMA_DBG_MAGIC) {
		EMSG("engr/rma/dbg: bad 2nd magic 0x%08x (expected 0x%08x)",
		     c->type_magic, SDM_CERT_TYPE_ENGR_RMA_DBG_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: %s ver=%u flags=0x%08x",
	     (hdr->cert_type == SDM_CERT_TYPE_ENGINEERING) ? "ENGR" :
	     (hdr->cert_type == SDM_CERT_TYPE_RMA) ? "RMA" : "DEBUG",
	     hdr->cert_ver, c->flags);
	return TEE_SUCCESS;
}

/*
 * 0x02 User AES Root Key.  cert_ver must be 0; 2nd magic mandatory.
 * Storage / wrap fields are sanity-checked against the doc's table.
 */
static TEE_Result check_aes_root_key(const void *cert, size_t cert_size,
				     const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_aes_root_key *c =
		(const struct sdm_cert_aes_root_key *)cert;
	uint32_t storage = 0;
	uint32_t wrap = 0;

	if (cert_size < sizeof(*c)) {
		EMSG("aes_root: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver != 0) {
		EMSG("aes_root: bad cert_ver %u (allowed: 0)", hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (c->type_magic != SDM_CERT_TYPE_AES_ROOT_MAGIC) {
		EMSG("aes_root: bad 2nd magic 0x%08x (expected 0x%08x)",
		     c->type_magic, SDM_CERT_TYPE_AES_ROOT_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}
	storage = c->storage_type & 0xFFU;
	wrap    = c->wrap_select  & 0xFFU;
	if (storage > 2U) {
		EMSG("aes_root: bad storage_type %u (allowed: 0..2)", storage);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (wrap > 3U) {
		EMSG("aes_root: bad wrap_select %u (allowed: 0..3)", wrap);
		return TEE_ERROR_BAD_FORMAT;
	}
	/* Off-chip storage rejects "Internal" wrap per the doc table */
	if (storage == 2U && wrap == 1U) {
		EMSG("aes_root: off-chip storage + internal wrap is invalid");
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: AES_ROOT_KEY ver=0 storage=%u wrap=%u",
	     storage, wrap);
	return TEE_SUCCESS;
}

/*
 * 0x05 COUNTER_SET_CERT.  SDM 1.5 removed the 2nd magic; the doc
 * keeps cert_ver in {0, 1}.  Counter type byte must be 0..6 or 255.
 */
static TEE_Result check_counter_set(const void *cert, size_t cert_size,
				    const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_counter_set *c =
		(const struct sdm_cert_counter_set *)cert;
	uint8_t counter_type = 0;

	if (cert_size < sizeof(*c)) {
		EMSG("counter_set: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver > 1) {
		EMSG("counter_set: bad cert_ver %u (allowed: 0, 1)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	counter_type = c->counter_type;
	if (counter_type > 6U && counter_type != 255U) {
		EMSG("counter_set: bad counter_type %u "
		     "(allowed: 0..6 or 255)", counter_type);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: COUNTER_SET ver=%u counter_type=%u value=%d",
	     hdr->cert_ver, counter_type, (int32_t)c->counter_value);
	return TEE_SUCCESS;
}

/*
 * 0x06 VAB_SRC_CERT - same shape sdm_cert_auth validates, but the
 * 2nd magic is version-sensitive (SDM 1.2 uses SDM_CERT_MAGIC_NUM
 * legacy; SDM 1.5 uses SDM_CERT_TYPE_VAB_SRC_15_MAGIC).
 */
static TEE_Result check_vab_src(const void *cert, size_t cert_size,
				const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_vab_src *c =
		(const struct sdm_cert_vab_src *)cert;
	uint32_t want_magic = 0;

	if (cert_size < sizeof(*c)) {
		EMSG("vab_src: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver > 1) {
		EMSG("vab_src: bad cert_ver %u (allowed: 0, 1)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	want_magic = (hdr->cert_ver == 1) ? SDM_CERT_TYPE_VAB_SRC_15_MAGIC
					  : SDM_CERT_MAGIC_NUM;
	if (c->vab_cert_magic_num != want_magic) {
		EMSG("vab_src: bad 2nd magic 0x%08x (expected 0x%08x for ver=%u)",
		     c->vab_cert_magic_num, want_magic, hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: VAB_SRC ver=%u flags=0x%08x",
	     hdr->cert_ver, c->flags);
	return TEE_SUCCESS;
}

/*
 * 0x07 Secondary (PR) Owner PUBKEY Auth.  cert_ver: 0 (FM) or 1 (SM).
 * Only SM specifies a 2nd magic; FM passes through unchecked.
 */
static TEE_Result check_pr_owner_pubkey(const void *cert, size_t cert_size,
					const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_pr_owner_pubkey *c =
		(const struct sdm_cert_pr_owner_pubkey *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("pr_owner_pk: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver > 1) {
		EMSG("pr_owner_pk: bad cert_ver %u (allowed: 0, 1)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver == 1 &&
	    c->type_magic != SDM_CERT_TYPE_PR_OWNER_PK_MAGIC) {
		EMSG("pr_owner_pk: bad 2nd magic 0x%08x (expected 0x%08x for SM)",
		     c->type_magic, SDM_CERT_TYPE_PR_OWNER_PK_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: PR_OWNER_PUBKEY ver=%u flags=0x%08x",
	     hdr->cert_ver, c->flags);
	return TEE_SUCCESS;
}

/*
 * 0x08 Kill Permit.  2nd magic == 0x4B696C6C ("Kill" ASCII).
 */
static TEE_Result check_kill_permit(const void *cert, size_t cert_size,
				    const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_kill_permit *c =
		(const struct sdm_cert_kill_permit *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("kill_permit: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver > 1) {
		EMSG("kill_permit: bad cert_ver %u (allowed: 0, 1)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (c->type_magic != SDM_CERT_TYPE_KILL_PERMIT_MAGIC) {
		EMSG("kill_permit: bad 2nd magic 0x%08x (expected 0x%08x)",
		     c->type_magic, SDM_CERT_TYPE_KILL_PERMIT_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: KILL_PERMIT ver=%u", hdr->cert_ver);
	return TEE_SUCCESS;
}

/*
 * 0x09 Owner Pubkey Late Provisioning.  cert_ver == 0; no 2nd magic.
 * The 48-byte root_hash at offset 0x20 must fit inside the buffer.
 */
static TEE_Result check_owner_pubkey_late(const void *cert, size_t cert_size,
					  const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_owner_pubkey_late *c =
		(const struct sdm_cert_owner_pubkey_late *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("owner_pk_late: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver != 0) {
		EMSG("owner_pk_late: bad cert_ver %u (allowed: 0)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	(void)c;
	IMSG("cert OK: OWNER_PUBKEY_LATE ver=0");
	return TEE_SUCCESS;
}

/*
 * 0x0A Decommission.  2nd magic == 0x6465636F ("deco" ASCII).
 */
static TEE_Result check_decommission(const void *cert, size_t cert_size,
				     const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_decommission *c =
		(const struct sdm_cert_decommission *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("decommission: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver > 1) {
		EMSG("decommission: bad cert_ver %u (allowed: 0, 1)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (c->type_magic != SDM_CERT_TYPE_DECOMMISSION_MAGIC) {
		EMSG("decommission: bad 2nd magic 0x%08x (expected 0x%08x)",
		     c->type_magic, SDM_CERT_TYPE_DECOMMISSION_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: DECOMMISSION ver=%u", hdr->cert_ver);
	return TEE_SUCCESS;
}

/*
 * 0x0B Cancel Old SDOS Service Root Key.  cert_ver must be 1.
 */
static TEE_Result check_cancel_sdos_srk(const void *cert, size_t cert_size,
					const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_cancel_sdos_srk *c =
		(const struct sdm_cert_cancel_sdos_srk *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("cancel_sdos_srk: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver != 1) {
		EMSG("cancel_sdos_srk: bad cert_ver %u (allowed: 1)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (c->type_magic != SDM_CERT_TYPE_CANCEL_SDOS_MAGIC) {
		EMSG("cancel_sdos_srk: bad 2nd magic 0x%08x (expected 0x%08x)",
		     c->type_magic, SDM_CERT_TYPE_CANCEL_SDOS_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: CANCEL_SDOS_SRK ver=1 fips_sel=0x%x",
	     (c->flags >> 29) & 0x3U);
	return TEE_SUCCESS;
}

/*
 * 0x0C Provision SDOS Service Root Key.  cert_ver in {0, 1}.
 */
static TEE_Result check_provision_sdos_srk(const void *cert,
					   size_t cert_size,
					   const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_provision_sdos_srk *c =
		(const struct sdm_cert_provision_sdos_srk *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("prov_sdos_srk: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver > 1) {
		EMSG("prov_sdos_srk: bad cert_ver %u (allowed: 0, 1)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (c->type_magic != SDM_CERT_TYPE_PROV_SDOS_MAGIC) {
		EMSG("prov_sdos_srk: bad 2nd magic 0x%08x (expected 0x%08x)",
		     c->type_magic, SDM_CERT_TYPE_PROV_SDOS_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: PROVISION_SDOS_SRK ver=%u entropy_words=%u virt=%u",
	     hdr->cert_ver, c->flags & 0xFU,
	     (c->flags >> 31) & 0x1U);
	return TEE_SUCCESS;
}

/*
 * 0x0D Cancel Old User AES Root Key.  cert_ver must be 2.  The doc
 * lists the 2nd magic as "0x187072118" (9 hex digits) -- we treat the
 * low 32 bits as authoritative and log the doc discrepancy.
 */
static TEE_Result check_cancel_user_aes(const void *cert, size_t cert_size,
					const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_cancel_user_aes *c =
		(const struct sdm_cert_cancel_user_aes *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("cancel_user_aes: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver != 2) {
		EMSG("cancel_user_aes: bad cert_ver %u (allowed: 2)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (c->type_magic != SDM_CERT_TYPE_CANCEL_AES_MAGIC) {
		EMSG("cancel_user_aes: bad 2nd magic 0x%08x "
		     "(expected 0x%08x; doc shows '0x187072118' "
		     "with 9 hex digits -- low 32 bits used)",
		     c->type_magic, SDM_CERT_TYPE_CANCEL_AES_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: CANCEL_USER_AES ver=2 cancel_all=%u",
	     c->flags & 0x1U);
	return TEE_SUCCESS;
}

/*
 * 0x0E Ownership Transfer (From) and 0x0F Ownership Transfer (To).
 * cert_ver must be 1.  Each side has its own 2nd magic.
 */
static TEE_Result check_ownership_xfer_from(const void *cert,
					    size_t cert_size,
					    const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_ownership_xfer_from *c =
		(const struct sdm_cert_ownership_xfer_from *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("own_xfer_from: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver != 1) {
		EMSG("own_xfer_from: bad cert_ver %u (allowed: 1)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (c->type_magic != SDM_CERT_TYPE_OWN_XFER_FROM_MAGIC) {
		EMSG("own_xfer_from: bad 2nd magic 0x%08x (expected 0x%08x)",
		     c->type_magic, SDM_CERT_TYPE_OWN_XFER_FROM_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: OWNERSHIP_XFER_FROM ver=1");
	return TEE_SUCCESS;
}

static TEE_Result check_ownership_xfer_to(const void *cert,
					  size_t cert_size,
					  const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_ownership_xfer_to *c =
		(const struct sdm_cert_ownership_xfer_to *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("own_xfer_to: truncated (%zu < %zu)",
		     cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	if (hdr->cert_ver != 1) {
		EMSG("own_xfer_to: bad cert_ver %u (allowed: 1)",
		     hdr->cert_ver);
		return TEE_ERROR_BAD_FORMAT;
	}
	if (c->type_magic != SDM_CERT_TYPE_OWN_XFER_TO_MAGIC) {
		EMSG("own_xfer_to: bad 2nd magic 0x%08x (expected 0x%08x)",
		     c->type_magic, SDM_CERT_TYPE_OWN_XFER_TO_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: OWNERSHIP_XFER_TO ver=1");
	return TEE_SUCCESS;
}

/*
 * 0x42444350 Beta Preview / 0x4244434C Beta Local -- no 2nd magic,
 * no cert_ver constraint in the doc.
 */
static TEE_Result check_beta(const void *cert, size_t cert_size,
			     const struct sdm_cert_hdr *hdr)
{
	const struct sdm_cert_beta *c =
		(const struct sdm_cert_beta *)cert;

	if (cert_size < sizeof(*c)) {
		EMSG("beta: truncated (%zu < %zu)", cert_size, sizeof(*c));
		return TEE_ERROR_BAD_FORMAT;
	}
	IMSG("cert OK: %s ver=%u beta_cycle=%u",
	     (hdr->cert_type == SDM_CERT_TYPE_BETA_PREVIEW) ? "BETA_PREVIEW"
							    : "BETA_LOCAL",
	     hdr->cert_ver, c->beta_cycle);
	return TEE_SUCCESS;
}


static TEE_Result validate_cert(const void *cert, size_t cert_size)
{
	const struct sdm_cert_hdr *hdr =
		(const struct sdm_cert_hdr *)cert;
	size_t max_data_sz = 0;

	if (cert_size < sizeof(*hdr)) {
		EMSG("cert: too small for common header (%zu < %zu)",
		     cert_size, sizeof(*hdr));
		return TEE_ERROR_BAD_FORMAT;
	}

	if (hdr->cert_magic_num != SDM_CERT_MAGIC_NUM) {
		EMSG("cert hdr: bad cert_magic_num 0x%08x (expected 0x%08x)",
		     hdr->cert_magic_num, SDM_CERT_MAGIC_NUM);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (hdr->cert_data_sz == 0) {
		EMSG("cert hdr: cert_data_sz is 0");
		return TEE_ERROR_BAD_FORMAT;
	}
	max_data_sz = cert_size;
	if ((size_t)hdr->cert_data_sz > max_data_sz) {
		EMSG("cert hdr: cert_data_sz %u > buffer total %zu",
		     hdr->cert_data_sz, max_data_sz);
		return TEE_ERROR_BAD_FORMAT;
	}

	DMSG("cert hdr: cert_data_sz=%u cert_ver=%u cert_type=0x%x",
	     hdr->cert_data_sz, hdr->cert_ver, hdr->cert_type);

	switch (hdr->cert_type) {
	case SDM_CERT_TYPE_ENGINEERING:
	case SDM_CERT_TYPE_RMA:
	case SDM_CERT_TYPE_DEBUG:
		return check_engr_rma_dbg(cert, cert_size, hdr);
	case SDM_CERT_TYPE_USER_AES_ROOT_KEY:
		return check_aes_root_key(cert, cert_size, hdr);
	case SDM_CERT_TYPE_COUNTER_SET:
		return check_counter_set(cert, cert_size, hdr);
	case SDM_CERT_TYPE_VAB_SRC:
		return check_vab_src(cert, cert_size, hdr);
	case SDM_CERT_TYPE_PR_OWNER_PUBKEY:
		return check_pr_owner_pubkey(cert, cert_size, hdr);
	case SDM_CERT_TYPE_KILL_PERMIT:
		return check_kill_permit(cert, cert_size, hdr);
	case SDM_CERT_TYPE_OWNER_PUBKEY_LATE:
		return check_owner_pubkey_late(cert, cert_size, hdr);
	case SDM_CERT_TYPE_DECOMMISSION:
		return check_decommission(cert, cert_size, hdr);
	case SDM_CERT_TYPE_CANCEL_SDOS_SRK:
		return check_cancel_sdos_srk(cert, cert_size, hdr);
	case SDM_CERT_TYPE_PROVISION_SDOS_SRK:
		return check_provision_sdos_srk(cert, cert_size, hdr);
	case SDM_CERT_TYPE_CANCEL_USER_AES:
		return check_cancel_user_aes(cert, cert_size, hdr);
	case SDM_CERT_TYPE_OWNERSHIP_XFER_FROM:
		return check_ownership_xfer_from(cert, cert_size, hdr);
	case SDM_CERT_TYPE_OWNERSHIP_XFER_TO:
		return check_ownership_xfer_to(cert, cert_size, hdr);
	case SDM_CERT_TYPE_BETA_PREVIEW:
	case SDM_CERT_TYPE_BETA_LOCAL:
		return check_beta(cert, cert_size, hdr);
	default:
		EMSG("cert hdr: unknown cert_type 0x%08x", hdr->cert_type);
		return TEE_ERROR_BAD_FORMAT;
	}
}


static TEE_Result do_send_cert(struct cert_sess_ctx *ctx,
			       uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	void *ns_cert = NULL;
	size_t cert_size = 0;
	uint8_t *local_cert = NULL;
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Zero the host's output before any return; populated by the PTA */
	params[1].value.a = 0;
	params[1].value.b = 0;

	if (param_types != exp_pt) {
		EMSG("bad param types 0x%08x", param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ns_cert   = params[0].memref.buffer;
	cert_size = params[0].memref.size;

	if (!ns_cert || cert_size == 0 || cert_size > SDM_CERT_MAX_SIZE) {
		EMSG("bad cert memref: buf=%p size=%zu (max %u)",
		     ns_cert, cert_size, SDM_CERT_MAX_SIZE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cert_size & 0x3U) {
		EMSG("cert size %zu not 4-byte aligned", cert_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cert_size < (size_t)VAB_CERT_MIN_SIZE) {
		EMSG("cert size %zu < minimum (%u)",
		     cert_size, (unsigned)VAB_CERT_MIN_SIZE);
		return TEE_ERROR_BAD_FORMAT;
	}

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  ns_cert, cert_size);
	if (res != TEE_SUCCESS) {
		EMSG("cert memref not readable: buf=%p size=%zu res=0x%08x",
		     ns_cert, cert_size, res);
		return res;
	}

	local_cert = TEE_Malloc(cert_size, 0);
	if (!local_cert) {
		EMSG("alloc local_cert (%zu) failed", cert_size);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_MemMove(local_cert, ns_cert, cert_size);

	res = validate_cert(local_cert, cert_size);
	if (res != TEE_SUCCESS) {
		/* Wipe the rejected cert before returning the heap memory */
		TEE_MemFill(local_cert, 0, cert_size);
		TEE_Free(local_cert);
		return res;
	}

	DMSG("sdm_send_cert: validated (%zu bytes), forwarding to PTA",
	     cert_size);

	pta_params[0].memref.buffer = local_cert;
	pta_params[0].memref.size   = cert_size;
	/* pta_params[1] (VALUE_OUTPUT) is zero-initialised */

	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_SDM_SEND_CERT, exp_pt,
				  pta_params, &pta_origin);

	/* Propagate SDM mailbox result to the host even on errors */
	params[1].value.a = pta_params[1].value.a;
	params[1].value.b = pta_params[1].value.b;

	TEE_MemFill(local_cert, 0, cert_size);
	TEE_Free(local_cert);

	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_SDM_SEND_CERT failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		return res;
	}

	DMSG("sdm_send_cert: SDM response mbox_err=0x%08x detail=0x%08x",
	     params[1].value.a, params[1].value.b);
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct cert_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return TEE_ERROR_BAD_STATE;

	switch (cmd_id) {
	case TA_SDM_SEND_CERT_CMD_SEND:
		return do_send_cert(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
