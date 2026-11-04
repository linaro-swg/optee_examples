// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_sdm_svc.h>
#include <sdm_prog_pubkey_ta.h>

struct pubkey_sess_ctx {
	TEE_TASessionHandle pta_sess;
};


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("sdm_prog_pubkey TA: create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("sdm_prog_pubkey TA: destroy");
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
	struct pubkey_sess_ctx *ctx = NULL;
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

	IMSG("sdm_prog_pubkey TA: session opened, PTA API v%u",
	     pta_params[0].value.a);
	*sess_ctx = ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct pubkey_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return;

	TEE_CloseTASession(ctx->pta_sess);
	TEE_Free(ctx);
	IMSG("sdm_prog_pubkey TA: session closed");
}


/* Reject the two cheapest "uninitialized buffer" sentinels: all-0x00,
 * all-0xFF.  A real SHA-256/384 hash hits one of these only by
 * astronomical accident (~2^-256 / 2^-384), so they almost certainly
 * mean a caller bug (forgot to read the file, wrong file, zero-init'd
 * but never populated).
 */
static bool hash_is_sentinel(const uint8_t *buf, size_t size)
{
	uint8_t and_all = 0xFF;
	uint8_t or_all  = 0x00;
	size_t i = 0;

	for (i = 0; i < size; i++) {
		and_all &= buf[i];
		or_all  |= buf[i];
	}
	/* all-0x00 -> or_all == 0; all-0xFF -> and_all == 0xFF */
	return (or_all == 0x00) || (and_all == 0xFF);
}

static bool validate_multi_hash_size(size_t in_size, size_t *unit_size,
				     size_t *hash_count)
{
	if (in_size == SDM_PUBKEY_HASH_SIZE_SHA256) {
		*unit_size  = SDM_PUBKEY_HASH_SIZE_SHA256;
		*hash_count = 1;
		return true;
	}

	if (in_size != 0 &&
	    (in_size % SDM_PUBKEY_HASH_SIZE_SHA384) == 0 &&
	    (in_size / SDM_PUBKEY_HASH_SIZE_SHA384) <=
		    SDM_PUBKEY_MAX_HASHES_PER_CALL) {
		*unit_size  = SDM_PUBKEY_HASH_SIZE_SHA384;
		*hash_count = in_size / SDM_PUBKEY_HASH_SIZE_SHA384;
		return true;
	}

	return false;
}


static TEE_Result do_prog_pubkey(struct pubkey_sess_ctx *ctx,
				 uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT);
	void *ns_in = NULL;
	size_t in_size = 0;
	size_t unit_size = 0;
	size_t hash_count = 0;
	size_t k = 0;
	uint32_t host_flags = 0;
	uint8_t *local_hash = NULL;
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt) {
		EMSG("bad param types 0x%08x", param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ns_in   = params[0].memref.buffer;
	in_size = params[0].memref.size;

	if (!ns_in) {
		EMSG("input memref buffer is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!validate_multi_hash_size(in_size, &unit_size, &hash_count)) {
		EMSG("invalid hash size %zu (expected %u=SHA-256, or a "
		     "multiple of %u=SHA-384 up to %ux)",
		     in_size, SDM_PUBKEY_HASH_SIZE_SHA256,
		     SDM_PUBKEY_HASH_SIZE_SHA384,
		     SDM_PUBKEY_MAX_HASHES_PER_CALL);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	host_flags = params[1].value.a;
	if (params[1].value.b != 0) {
		EMSG("param[1].value.b must be 0 (got 0x%08x)",
		     params[1].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (host_flags & ~SDM_PUBKEY_HOST_FLAGS_VALID_MASK) {
		EMSG("unknown host flag bits 0x%08x", host_flags);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  ns_in, in_size);
	if (res != TEE_SUCCESS) {
		EMSG("input memref not readable: buf=%p size=%zu res=0x%08x",
		     ns_in, in_size, res);
		return res;
	}

	/* Snapshot first, then sanity-check the snapshot (not the NW
	 * buffer) so the sentinel test cannot be raced. */
	local_hash = TEE_Malloc(in_size, 0);
	if (!local_hash) {
		EMSG("alloc local_hash (%zu) failed", in_size);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(local_hash, ns_in, in_size);

	/* Every hash chunk in the batch must independently pass the
	 * sentinel check - one all-0x00/all-0xFF chunk means at least one
	 * of the host's -i files is bogus, even if the others are fine. */
	for (k = 0; k < hash_count; k++) {
		if (hash_is_sentinel(local_hash + k * unit_size, unit_size)) {
			EMSG("hash #%zu of %zu is all-0x00 or all-0xFF - rejecting",
			     k + 1, hash_count);
			res = TEE_ERROR_BAD_PARAMETERS;
			goto wipe_and_free;
		}
	}

	if (host_flags & SDM_PUBKEY_HOST_FLAG_NON_VOLATILE)
		EMSG("sdm_prog_pubkey TA: NON_VOLATILE requested "
		     "(hash=%s, count=%zu) - PTA will permanently burn "
		     "the owner-root key eFuse(s)",
		     unit_size == SDM_PUBKEY_HASH_SIZE_SHA256 ? "secp256r1"
							      : "secp384r1",
		     hash_count);
	else
		IMSG("sdm_prog_pubkey TA: ***** Virtual ***** "
		     "(hash=%s, count=%zu, T=1, cache-only)",
		     unit_size == SDM_PUBKEY_HASH_SIZE_SHA256 ? "secp256r1"
							      : "secp384r1",
		     hash_count);

	pta_params[0].memref.buffer = local_hash;
	pta_params[0].memref.size   = in_size;
	pta_params[1].value.a       = host_flags;
	pta_params[1].value.b       = 0;
	/* params[2]/[3] populated by PTA */

	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_SDM_PROG_PUBKEY, exp_pt,
				  pta_params, &pta_origin);

	/* Always propagate the PTA's response values back to the host -
	 * even on PTA failure the SDM may have left meaningful status in
	 * param[2]/[3] (e.g. SDM rejected the hash). */
	params[2].value.a = pta_params[2].value.a;
	params[2].value.b = pta_params[2].value.b;
	params[3].value.a = pta_params[3].value.a;
	params[3].value.b = pta_params[3].value.b;

	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_SDM_PROG_PUBKEY failed: 0x%08x (origin 0x%x), "
		     "sdm_resp=0x%08x phase2=0x%08x",
		     res, pta_origin,
		     params[2].value.a, params[3].value.a);
		goto wipe_and_free;
	}

	DMSG("sdm_prog_pubkey: PTA returned ok (sdm_resp=0x%08x phase2=0x%08x "
	     "submitted=%u)",
	     params[2].value.a, params[3].value.a, params[3].value.b);

wipe_and_free:
	TEE_MemFill(local_hash, 0, in_size);
	TEE_Free(local_hash);
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct pubkey_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return TEE_ERROR_BAD_STATE;

	switch (cmd_id) {
	case TA_SDM_PROG_PUBKEY_CMD_SET:
		return do_prog_pubkey(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
