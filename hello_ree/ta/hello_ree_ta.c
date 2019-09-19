/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* 
 * This UTA calls out for the REE service to satisfy a request. The requests
 * are pre-negotiated with Client Application (CA) - same as between CA and
 * UTA for getting the Trusted services.
 *
 * The UTA has no knowledge if the service is implemented as Message Queue or
 * as a Dynamic Library. It will used the UUID to uniquely identify the service
 * and send the requests to it.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_api_types_extensions.h>
#include <tee_api_extensions.h>

#include <hello_ree_ta.h>
#include <string.h>

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World! I can invoke services from REE!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

/**
 * invoke_ree_service() - call the REE service
 */
static TEE_Result invoke_ree_service(TEE_UUID *uuid)
{
	char msg_to_ree[] = "Hello! from TEE";
	ree_session_handle ree_sess = NULL;
	TEE_Result result = TEE_SUCCESS;
	TEE_Param ree_params[4] = {0};
	uint32_t param_types;
	uint32_t ret_origin = 0;

	DMSG("Opening a session on REE service\n");

	/* Open a session on REE service identified by UUID */
	result = TEE_OpenREESession(uuid, 0, 0, NULL, &ree_sess, &ret_origin);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to open up REE Session\n");
		goto err;
	}

	/* Send a custom command */
	param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, /* Reserved */
			TEE_PARAM_TYPE_MEMREF_INPUT,
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE);
	/* Outgoing data to REE service */
	ree_params[1].memref.buffer = msg_to_ree;
	ree_params[1].memref.size = sizeof(msg_to_ree);

	/* Incoming data from REE service */
	ree_params[2].memref.buffer = TEE_Malloc(64, TEE_MALLOC_FILL_ZERO);
	ree_params[2].memref.size = 64;

	if (!ree_params[2].memref.buffer)
		goto err;

	DMSG("Invoking command on REE service\n");
	result = TEE_InvokeREECommand(ree_sess, 0,
			HELLO_REE_EXCHANGE_GREETINGS,
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
	EMSG("REE filled buffer: %s\n", (char *)ree_params[2].memref.buffer);

err:
	if (ree_params[2].memref.buffer)
		TEE_Free(ree_params[2].memref.buffer);
	if (ree_sess)
		TEE_CloseREESession(ree_sess);
	return result;
}

static TEE_Result fill_random(uint32_t param_types, TEE_Param params[4])
{
	int i;
	TEE_Result result = TEE_SUCCESS;
	TEE_UUID uuid[] = {
		TA_HELLO_REE_MSGQ_REE_UUID,
		TA_HELLO_REE_DLL_REE_UUID
	};
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Fill the random number */
	TEE_GenerateRandom(&params[0].value.a, sizeof(params[0].value.a));

	/* Invoke both the REE services */
	for (i = 0; i < sizeof(uuid)/sizeof(TEE_UUID); i++)
		result |= invoke_ree_service(&uuid[i]);

	if (result != TEE_SUCCESS)
		result = TEE_ERROR_BAD_PARAMETERS;

	return result;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
		uint32_t cmd_id,
		uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_HELLO_REE_FILL_RANDOM_NUMBER:
		return fill_random(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
