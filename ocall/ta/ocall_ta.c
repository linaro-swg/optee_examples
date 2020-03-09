/*
 * Copyright (c) 2020, Microsoft Corporation
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <ocall_ta.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

static TEE_Result call_ca(uint32_t param_types,
			  TEE_Param params[TEE_NUM_PARAMS])
{
	char buf1[128] = { 0 };
	char buf2[128] = { 0 };

	const char *msg1 = "This string was sent by the TA";
	const char *msg2 = "The TA thinks this is a fun riddle";

	TEE_Param ocall_params[TEE_NUM_PARAMS];

	TEE_Result res = TEE_SUCCESS;
	uint32_t eorig = TEE_ORIGIN_TRUSTED_APP;

	/* Expected parameter types for the function invocation */
	const uint32_t expected_pt =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INOUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INOUT);

	/* Parameter types for the OCALL (can be different from the above) */
	const uint32_t ocall_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INOUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INOUT);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[2].memref.buffer || !params[3].memref.buffer) {
		EMSG("No buffer(s)");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[3].memref.size < strlen(msg2) + 1)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Print the invocation's INPUT/INOUT parameters */
	DMSG("Input values: %u, %u", params[0].value.a, params[0].value.b);
	DMSG("Inout values: %u, %u", params[1].value.a, params[1].value.b);

	DMSG("Input string: %s", (char *)params[2].memref.buffer);
	DMSG("Input size: %u", params[2].memref.size);

	DMSG("Inout string: %s", (char *)params[3].memref.buffer);
	DMSG("Inout size: %u", params[3].memref.size);

	/* Set the invocation's INOUT parameters */
	params[1].value.a = 0xE;
	params[1].value.b = 0xF;

	params[3].memref.size = strlen(msg2) + 1;
	memcpy(params[3].memref.buffer, msg2, params[3].memref.size);

	/* Set the OCALL's INPUT/INOUT parameters */
	ocall_params[0].value.a = 0x1;
	ocall_params[0].value.b = 0x2;

	ocall_params[1].value.a = 0xA;
	ocall_params[1].value.b = 0xB;

	memcpy(buf1, msg1, strlen(msg1) + 1);
	memcpy(buf2, msg2, strlen(msg2) + 1);

	ocall_params[2].memref.buffer = buf1;
	ocall_params[2].memref.size = sizeof(buf1);

	ocall_params[3].memref.buffer = buf2;
	ocall_params[3].memref.size = sizeof(buf2);

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE, CA_OCALL_CMD_REPLY_TA,
				  ocall_param_types, ocall_params, &eorig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);
		return res;
	}

	if (!ocall_params[3].memref.buffer) {
		EMSG("Bad parameters");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Print the OCALL's INOUT parameters */
	DMSG("Output values: %u, %u", ocall_params[1].value.a,
	     ocall_params[1].value.b);
	DMSG("Output string: \"%s\"", (char *)ocall_params[3].memref.buffer);
	DMSG("Output size: %u\n", ocall_params[3].memref.size);

	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* NOTHING */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[4] __unused,
				    void **sess_ctx __unused)
{
	const char *msg = "The TA says hello during session open";

	TEE_Param ocall_params[TEE_NUM_PARAMS];

	TEE_Result res = TEE_SUCCESS;
	uint32_t eorig = TEE_ORIGIN_TRUSTED_APP;

	/* Expected parameter types for the function invocation */
	const uint32_t expected_pt =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/* Parameter types for the OCALL (can be different from the above) */
	const uint32_t ocall_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_MEMREF_INPUT);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!params[1].memref.buffer) {
		EMSG("No buffer");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Print the invocation's INPUT parameters */
	DMSG("Input values: 0x%x, 0x%x", params[0].value.a, params[0].value.b);
	DMSG("Input string: %s", (char *)params[1].memref.buffer);
	DMSG("Input size: %u", params[1].memref.size);

	/* Set the OCALL's parameters */
	ocall_params[0].value.a = 0xFCFAFFFE;
	ocall_params[0].value.b = 0x10CDDC01;

	ocall_params[3].memref.buffer = (void *)msg;
	ocall_params[3].memref.size = strlen(msg) + 1;

	res = TEE_InvokeCACommand(TEE_TIMEOUT_INFINITE,
				  CA_OCALL_CMD_REPLY_SESSION_OPEN,
				  ocall_param_types, ocall_params, &eorig);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_InvokeCACommand failed with code 0x%x origin 0x%x",
			res, eorig);
		return res;
	}

	/* Print the OCALL's INOUT parameters */
	DMSG("Output values: 0x%x, 0x%x", ocall_params[0].value.a,
	     ocall_params[0].value.b);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx __unused)
{
	/* NOTHING */
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __unused, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case TA_OCALL_CMD_CALL_CA:
		return call_ca(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
