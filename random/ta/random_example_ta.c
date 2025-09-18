// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <random_ta.h>

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
}

static TEE_Result random_number_generate(uint32_t param_types,
					 TEE_Param params[4])
{
	uint32_t exp_param_types =
				TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	void *buf = NULL;

	DMSG("has been called");
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	buf = TEE_Malloc(params[0].memref.size, 0);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;
	IMSG("Generating random data over %u bytes.", params[0].memref.size);
	/*
	 * The TEE_GenerateRandom function is a part of TEE Internal Core API,
	 * which generates random data
	 *
	 * Parameters:
	 * @ randomBuffer : Reference to generated random data
	 * @ randomBufferLen : Byte length of requested random data
	 */
	TEE_GenerateRandom(buf, params[0].memref.size);
	TEE_MemMove(params[0].memref.buffer, buf, params[0].memref.size);
	TEE_Free(buf);

	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_RANDOM_CMD_GENERATE:
		return random_number_generate(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
