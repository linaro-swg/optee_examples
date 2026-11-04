// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_sdm_svc.h>
#include <sdm_security_op_ta.h>

struct secop_sess_ctx {
	TEE_TASessionHandle pta_sess;
};


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("sdm_security_op TA: create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("sdm_security_op TA: destroy");
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
	struct secop_sess_ctx *ctx = NULL;
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

	IMSG("sdm_security_op TA: session opened, PTA API v%u",
	     pta_params[0].value.a);
	*sess_ctx = ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct secop_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return;

	TEE_CloseTASession(ctx->pta_sess);
	TEE_Free(ctx);
	IMSG("sdm_security_op TA: session closed");
}


/* Returns TEE_SUCCESS if rules pass, else TEE_ERROR_BAD_PARAMETERS. */
static TEE_Result validate_option_word(uint32_t opt_clean)
{
	uint32_t reserved = 0;

	if (opt_clean == 0) {
		EMSG("empty option word - at least one SDM_SECOPT_* bit "
		     "must be set");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	reserved = opt_clean & ~SDM_SECOPT_FUNCTIONAL_MASK;
	if (reserved) {
		EMSG("reserved bits set in option word: 0x%08x "
		     "(allowed mask 0x%08x)",
		     reserved, SDM_SECOPT_FUNCTIONAL_MASK);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Rule A: VIRTUAL_EFUSE_DISABLE (bit 4) must be exclusive.
	 * If it's set together with anything else, the request is
	 * inconsistent - reject.
	 */
	if ((opt_clean & SDM_SECOPT_VIRTUAL_EFUSE_DISABLE) &&
	    (opt_clean != SDM_SECOPT_VIRTUAL_EFUSE_DISABLE)) {
		EMSG("rule A violation: VIRTUAL_EFUSE_DISABLE (bit 4) "
		     "must be the only option in the command "
		     "(got 0x%08x, other bits: 0x%08x)",
		     opt_clean,
		     opt_clean & ~SDM_SECOPT_VIRTUAL_EFUSE_DISABLE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if ((opt_clean & SDM_SECOPT_JTAG_DISABLE) &&
	    !(opt_clean & SDM_SECOPT_CRC_ENABLE)) {
		EMSG("rule B violation: JTAG_DISABLE (bit 2) requires "
		     "CRC_ENABLE (bit 12); option_word=0x%08x",
		     opt_clean);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return TEE_SUCCESS;
}


static TEE_Result do_security_op(struct secop_sess_ctx *ctx,
				 uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	uint32_t opt_raw = 0;
	uint32_t opt_clean = 0;
	uint32_t host_flags = 0;
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt) {
		EMSG("bad param types 0x%08x", param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	opt_raw    = params[0].value.a;
	host_flags = params[1].value.a;

	if (params[0].value.b != 0) {
		EMSG("param[0].value.b must be 0 (got 0x%08x)",
		     params[0].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (params[1].value.b != 0) {
		EMSG("param[1].value.b must be 0 (got 0x%08x)",
		     params[1].value.b);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (host_flags & ~SDM_SECOPT_HOST_FLAGS_VALID_MASK) {
		EMSG("unknown host flag bits 0x%08x", host_flags);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Strip TEST_MODE - PTA owns it.  The cleaned word is what
	 * the user actually asked for, and what business rules act on. */
	opt_clean = opt_raw & ~SDM_SECOPT_TEST_MODE;

	res = validate_option_word(opt_clean);
	if (res != TEE_SUCCESS)
		return res;

	if (host_flags & SDM_SECOPT_HOST_FLAG_NON_VOLATILE)
		EMSG("sdm_security_op TA: NON_VOLATILE requested - "
		     "PTA will permanently burn eFuse bits for "
		     "option_word=0x%08x",
		     opt_clean);

	pta_params[0].value.a = opt_clean;
	pta_params[0].value.b = 0;
	pta_params[1].value.a = host_flags;
	pta_params[1].value.b = 0;

	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_SDM_SECURITY_OP, exp_pt,
				  pta_params, &pta_origin);
	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_SDM_SECURITY_OP failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		return res;
	}

	DMSG("sdm_security_op: applied option_word=0x%08x (host_flags=0x%08x)",
	     opt_clean, host_flags);
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct secop_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return TEE_ERROR_BAD_STATE;

	switch (cmd_id) {
	case TA_SDM_SECURITY_OP_CMD_APPLY:
		return do_security_op(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
