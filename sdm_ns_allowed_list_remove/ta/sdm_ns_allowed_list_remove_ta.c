// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_sdm_svc.h>
#include <sdm_ns_allowed_list_remove_ta.h>

/* ARM SMCCC bit layout (relevant subset) */
#define SMCCC_OEN_MASK		((uint32_t)0x3F << 24)
#define SMCCC_OEN_SHIFT		24
#define SMCCC_OEN_SIP		0x02
#define SMCCC_RESERVED_MASK	((uint32_t)0xFF << 16)

struct nsalr_sess_ctx {
	TEE_TASessionHandle pta_sess;
};


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("sdm_ns_allowed_list_remove TA: create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("sdm_ns_allowed_list_remove TA: destroy");
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
	struct nsalr_sess_ctx *ctx = NULL;
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

	IMSG("sdm_ns_allowed_list_remove TA: session opened, PTA API v%u",
	     pta_params[0].value.a);
	*sess_ctx = ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct nsalr_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return;

	TEE_CloseTASession(ctx->pta_sess);
	TEE_Free(ctx);
	IMSG("sdm_ns_allowed_list_remove TA: session closed");
}


static bool is_well_formed_sip_fid(uint32_t fid)
{
	uint32_t oen = (fid & SMCCC_OEN_MASK) >> SMCCC_OEN_SHIFT;

	if (oen != SMCCC_OEN_SIP)
		return false;
	if (fid & SMCCC_RESERVED_MASK)
		return false;

	return true;
}


static TEE_Result do_ns_allowed_list_remove(struct nsalr_sess_ctx *ctx,
					    uint32_t param_types,
					    TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	uint32_t fid = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt) {
		EMSG("bad param types 0x%08x (expected VALUE_INPUT, NONE, NONE, NONE)",
		     param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[0].value.b != 0) {
		EMSG("param[0].value.b must be 0 (got 0x%08x)",
		     params[0].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	fid = params[0].value.a;

	if (!is_well_formed_sip_fid(fid)) {
		EMSG("0x%08" PRIx32 " is not a well-formed SiP FID "
		     "(need OEN=0x02 and bits[23:16]=0)", fid);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	pta_params[0].value.a = fid;
	pta_params[0].value.b = 0;

	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_SDM_NS_ALLOWED_LIST_REMOVE, exp_pt,
				  pta_params, &pta_origin);
	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_SDM_NS_ALLOWED_LIST_REMOVE failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		return res;
	}

	DMSG("sdm_ns_allowed_list_remove: SDM accepted (FID=0x%08" PRIx32 ")",
	     fid);
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct nsalr_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return TEE_ERROR_BAD_STATE;

	switch (cmd_id) {
	case TA_SDM_NS_ALLOWED_LIST_REMOVE_CMD_APPLY:
		return do_ns_allowed_list_remove(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
