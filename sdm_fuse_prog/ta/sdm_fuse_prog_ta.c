// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_sdm_svc.h>
#include <sdm_fuse_prog_ta.h>

struct fuse_prog_sess_ctx {
	TEE_TASessionHandle pta_sess;
};


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("sdm_fuse_prog TA: create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("sdm_fuse_prog TA: destroy");
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
	struct fuse_prog_sess_ctx *ctx = NULL;
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

	IMSG("sdm_fuse_prog TA: session opened, PTA API v%u",
	     pta_params[0].value.a);
	*sess_ctx = ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct fuse_prog_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return;

	TEE_CloseTASession(ctx->pta_sess);
	TEE_Free(ctx);
	IMSG("sdm_fuse_prog TA: session closed");
}


static TEE_Result do_fuse_prog(struct fuse_prog_sess_ctx *ctx,
			       uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	void *ns_in = NULL;
	size_t in_size = 0;
	void *local_fuses = NULL;
	uint32_t host_flags = 0;
	bool non_volatile = false;
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

	if (in_size != SDM_USER_FUSE_SIZE) {
		EMSG("input size %zu != SDM_USER_FUSE_SIZE (%u)",
		     in_size, SDM_USER_FUSE_SIZE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[1].value.b != 0) {
		EMSG("reserved param[1].b must be 0 (got 0x%08x)",
		     params[1].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	host_flags = params[1].value.a;
	non_volatile = (host_flags & SDM_FUSE_PROG_HOST_FLAG_NON_VOLATILE) != 0;

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  ns_in, in_size);
	if (res != TEE_SUCCESS) {
		EMSG("input memref not readable: buf=%p size=%zu res=0x%08x",
		     ns_in, in_size, res);
		return res;
	}

	local_fuses = TEE_Malloc(in_size, 0);
	if (!local_fuses) {
		EMSG("alloc local_fuses (%zu) failed", in_size);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_MemMove(local_fuses, ns_in, in_size);

	pta_params[0].memref.buffer = local_fuses;
	pta_params[0].memref.size   = in_size;
	pta_params[1].value.a       = host_flags;
	pta_params[1].value.b       = 0;

	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_SDM_PROG_USER_FUSES, exp_pt,
				  pta_params, &pta_origin);

	/*
	 * Wipe the snapshot before returning the heap memory.  Fuse
	 * values may be ownership-bound secrets in both virtual and
	 * physical modes — don't let them linger in recycled pages.
	 */
	TEE_MemFill(local_fuses, 0, in_size);
	TEE_Free(local_fuses);

	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_SDM_PROG_USER_FUSES failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		return res;
	}

	DMSG("sdm_fuse_prog: programmed %u %s fuse words",
	     SDM_USER_FUSE_COUNT,
	     non_volatile ? "PHYSICAL (eFuse-burned)" : "virtual");
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct fuse_prog_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return TEE_ERROR_BAD_STATE;

	switch (cmd_id) {
	case TA_SDM_FUSE_PROG_CMD_SET:
		return do_fuse_prog(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
