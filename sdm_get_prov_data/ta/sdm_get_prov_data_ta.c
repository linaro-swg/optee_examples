// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_sdm_svc.h>
#include <sdm_get_prov_data_ta.h>

struct prov_sess_ctx {
	TEE_TASessionHandle pta_sess;
};


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("sdm_get_prov_data TA: create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("sdm_get_prov_data TA: destroy");
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
	struct prov_sess_ctx *ctx = NULL;
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

	IMSG("sdm_get_prov_data TA: session opened, PTA API v%u",
	     pta_params[0].value.a);
	*sess_ctx = ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct prov_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return;

	TEE_CloseTASession(ctx->pta_sess);
	TEE_Free(ctx);
	IMSG("sdm_get_prov_data TA: session closed");
}


static TEE_Result validate_prov_blob(const uint32_t *w, size_t actual_size)
{
	uint32_t cosign = 0;
	uint32_t hash_count = 0;
	uint32_t hash_type = 0;
	uint32_t expected_words = 0;
	uint32_t expected_size = 0;

	if (actual_size == 0 || actual_size > SDM_PROV_DATA_MAX_SIZE) {
		EMSG("prov size %zu out of range (max %u)",
		     actual_size, SDM_PROV_DATA_MAX_SIZE);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (actual_size & 0x3U) {
		EMSG("prov size %zu not 4-byte aligned", actual_size);
		return TEE_ERROR_BAD_FORMAT;
	}

	/* Must hold at least the 3-word header to extract cosign_info */
	if (actual_size < 3U * 4U) {
		EMSG("prov size %zu < 3-word header", actual_size);
		return TEE_ERROR_BAD_FORMAT;
	}

	cosign     = w[2];
	hash_count = SDM_PROV_HASH_COUNT(cosign);
	hash_type  = SDM_PROV_HASH_TYPE(cosign);

	if (hash_count < 1U || hash_count > SDM_PROV_MAX_HASHES) {
		EMSG("prov: hash_count %u out of [1, %u] (cosign=0x%08x)",
		     hash_count, SDM_PROV_MAX_HASHES, cosign);
		return TEE_ERROR_BAD_FORMAT;
	}

	/* The exact size dictated by the layout for this hash_count */
	expected_words = 3U + hash_count * (SDM_PROV_HASH_WORDS + 1U) + 6U;
	expected_size  = expected_words * 4U;

	if ((uint32_t)actual_size != expected_size) {
		EMSG("prov: size %zu != expected %u (hash_count=%u, cosign=0x%08x)",
		     actual_size, expected_size, hash_count, cosign);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (hash_type != SDM_PROV_HASH_TYPE_SECP384R1)
		IMSG("prov: hash_type %u (expected %u=secp384r1)",
		     hash_type, SDM_PROV_HASH_TYPE_SECP384R1);

	DMSG("prov OK: %zu bytes, hash_count=%u, hash_type=%u",
	     actual_size, hash_count, hash_type);
	return TEE_SUCCESS;
}


static TEE_Result do_get_prov_data(struct prov_sess_ctx *ctx,
				   uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	void *ns_out = NULL;
	size_t ns_out_size = 0;
	void *local_buf = NULL;
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	size_t actual_size = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt) {
		EMSG("bad param types 0x%08x", param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ns_out      = params[0].memref.buffer;
	ns_out_size = params[0].memref.size;

	if (!ns_out) {
		EMSG("output memref buffer is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (ns_out_size < SDM_PROV_DATA_MAX_SIZE) {
		EMSG("output memref size %zu < SDM_PROV_DATA_MAX_SIZE (%u)",
		     ns_out_size, SDM_PROV_DATA_MAX_SIZE);
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  ns_out, ns_out_size);
	if (res != TEE_SUCCESS) {
		EMSG("output memref not writable: buf=%p size=%zu res=0x%08x",
		     ns_out, ns_out_size, res);
		return res;
	}

	local_buf = TEE_Malloc(SDM_PROV_DATA_MAX_SIZE, TEE_MALLOC_FILL_ZERO);
	if (!local_buf) {
		EMSG("alloc local_buf (%u) failed", SDM_PROV_DATA_MAX_SIZE);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	pta_params[0].memref.buffer = local_buf;
	pta_params[0].memref.size   = SDM_PROV_DATA_MAX_SIZE;

	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_SDM_GET_PROV_DATA, exp_pt,
				  pta_params, &pta_origin);
	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_SDM_GET_PROV_DATA failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		TEE_Free(local_buf);
		return res;
	}

	actual_size = pta_params[0].memref.size;

	res = validate_prov_blob((const uint32_t *)local_buf, actual_size);
	if (res != TEE_SUCCESS) {
		/* Don't leak a malformed blob to NW; report and bail */
		TEE_Free(local_buf);
		return res;
	}

	if (actual_size > ns_out_size) {
		EMSG("internal: actual %zu > ns_out_size %zu",
		     actual_size, ns_out_size);
		TEE_Free(local_buf);
		return TEE_ERROR_GENERIC;
	}

	TEE_MemMove(ns_out, local_buf, actual_size);
	params[0].memref.size = actual_size;

	TEE_Free(local_buf);

	DMSG("sdm_get_prov_data: returned %zu bytes to NW", actual_size);
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct prov_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return TEE_ERROR_BAD_STATE;

	switch (cmd_id) {
	case TA_SDM_GET_PROV_DATA_CMD_GET:
		return do_get_prov_data(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
