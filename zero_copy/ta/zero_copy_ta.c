/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_api_types_extensions.h>
#include <tee_api_extensions.h>

#include <zero_copy_ta.h>
#include <string.h>

struct zero_copy_ta_ctx {
	void *mem;
	size_t size;
} zcopy_ctx;

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

/**
 * TA_OpenSessionEntryPoint() - Open session on zero copy TA
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/* Nothing to do */
	return TEE_SUCCESS;
}

/**
 * TA_CloseSessionEntryPoint() - close the session on this TA
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	zcopy_ctx.mem = NULL;
}

/**
 * invoke_zcopy_ree_service() - call the REE service
 */
static TEE_Result invoke_zcopy_ree_service(void)
{
	int count;
	TEE_UUID uuid = REE_ZERO_COPY_MSGQ_UUID;
	ree_session_handle ree_sess = NULL;
	TEE_Result result = TEE_SUCCESS;
	TEE_Param ree_params[4] = {0};
	uint32_t param_types;
	uint32_t ret_origin = 0;

	DMSG("Opening a session on Zcopy REE service\n");

	/* Open a session on REE service identified by UUID */
	result = TEE_OpenREESession(&uuid, 0, 0, NULL, &ree_sess, &ret_origin);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to open up REE Session\n");
		goto err;
	}

	/* Send a custom command */
	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	for (count = 0; count < 10; count++) {
		/* Write something in shared buffer */
		snprintf(zcopy_ctx.mem, zcopy_ctx.size, "Hello from TEE %d", count);

		DMSG("Invoking command on REE service\n");
		result = TEE_InvokeREECommand(ree_sess, 0,
				REE_ZERO_COPY_FILL_BUFFER,
				param_types, ree_params, &ret_origin);
		if (result != TEE_SUCCESS) {
			DMSG("Failed to invoke REE command\n");
			goto err;
		}

		/*
		 * Expecting a string. The user of REE service is expected
		 * to be careful while reading the string data and not read
		 * more than the buffer allocated. This is just for reference.
		 */
		EMSG("REE->TEE: %s\n", (char *)zcopy_ctx.mem);
	}

err:
	if (ree_sess)
		TEE_CloseREESession(ree_sess);
	return result;
}

static TEE_Result access_shared_mem(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result result = TEE_SUCCESS;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	zcopy_ctx.mem  = params[0].memref.buffer;
	zcopy_ctx.size = params[0].memref.size;

	/* Invoke zcopy REE service */
	result = invoke_zcopy_ree_service();
	if (result != TEE_SUCCESS)
		result = TEE_ERROR_BAD_PARAMETERS;

	return result;
}

/**
 * TA_InvokeCommandEntryPoint() - invoke the commands on TA
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
		uint32_t cmd_id,
		uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_ZERO_COPY_FILL_SHARED_MEM:
		return access_shared_mem(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
