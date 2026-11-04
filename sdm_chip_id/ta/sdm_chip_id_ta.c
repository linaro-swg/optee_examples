// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_sdm_svc.h>
#include <sdm_chip_id_ta.h>

struct chip_id_sess_ctx {
	TEE_TASessionHandle pta_sess;
};

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("sdm_chip_id TA: create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("sdm_chip_id TA: destroy");
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
	struct chip_id_sess_ctx *ctx = NULL;
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

	IMSG("sdm_chip_id TA: session opened, PTA API v%u",
	     pta_params[0].value.a);
	*sess_ctx = ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct chip_id_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return;

	TEE_CloseTASession(ctx->pta_sess);
	TEE_Free(ctx);
	IMSG("sdm_chip_id TA: session closed");
}

static TEE_Result chip_id_get(struct chip_id_sess_ctx *ctx,
			      uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_SDM_GET_CHIP_ID, exp_pt,
				  pta_params, &pta_origin);
	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_SDM_GET_CHIP_ID failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		return res;
	}

	params[0].value.a = pta_params[0].value.a;
	params[0].value.b = pta_params[0].value.b;

	DMSG("chip_id = 0x%08x%08x",
	     params[0].value.b, params[0].value.a);
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct chip_id_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return TEE_ERROR_BAD_STATE;

	switch (cmd_id) {
	case TA_SDM_CHIP_ID_CMD_GET:
		return chip_id_get(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
