// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_sdm_svc.h>
#include <sdm_get_random_ta.h>

struct rng_sess_ctx {
	TEE_TASessionHandle pta_sess;
};

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("sdm_get_random TA: create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("sdm_get_random TA: destroy");
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
	struct rng_sess_ctx *ctx = NULL;
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

	IMSG("sdm_get_random TA: session opened, PTA API v%u",
	     pta_params[0].value.a);
	*sess_ctx = ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct rng_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return;

	TEE_CloseTASession(ctx->pta_sess);
	TEE_Free(ctx);
	IMSG("sdm_get_random TA: session closed");
}

static TEE_Result do_get_random(struct rng_sess_ctx *ctx,
				uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	uint32_t size = 0;
	void *ns_out = NULL;
	size_t out_size = 0;
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt) {
		EMSG("bad param types 0x%08x", param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	size     = params[0].value.a;
	ns_out   = params[1].memref.buffer;
	out_size = params[1].memref.size;

	if (size < SDM_RNG_MIN_BYTES || size > SDM_RNG_MAX_BYTES) {
		EMSG("requested size %u out of range [%u..%u]",
		     size, SDM_RNG_MIN_BYTES, SDM_RNG_MAX_BYTES);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (size & 0x3U) {
		EMSG("requested size %u not 4-byte aligned", size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!ns_out || out_size < size) {
		EMSG("output memref invalid: buf=%p size=%zu (need %u)",
		     ns_out, out_size, size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  ns_out, size);
	if (res != TEE_SUCCESS) {
		EMSG("output memref not writable: out=%p size=%u res=0x%08x",
		     ns_out, size, res);
		return res;
	}

	DMSG("sdm_get_random: validated (size=%u)", size);

	/* Forward to PTA - the PTA writes random data directly into ns_out */
	pta_params[0].value.a       = size;
	pta_params[1].memref.buffer = ns_out;
	pta_params[1].memref.size   = out_size;

	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_SDM_GET_RANDOM, exp_pt,
				  pta_params, &pta_origin);

	params[1].memref.size = pta_params[1].memref.size;

	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_SDM_GET_RANDOM failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		return res;
	}

	DMSG("sdm_get_random: OK, %zu bytes",
	     (size_t)params[1].memref.size);
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct rng_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return TEE_ERROR_BAD_STATE;

	switch (cmd_id) {
	case TA_SDM_GET_RANDOM_CMD_GET:
		return do_get_random(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
