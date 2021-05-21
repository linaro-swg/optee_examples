/*
 * Copyright (c) 2020, Microsoft Corporation
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <tee_client_api_extensions.h>

#include <ocall_ta.h>

static void print_uuid(TEEC_UUID *uuid)
{
	printf("%x-%x-%x-%x%x-%x%x%x%x%x%x",
		uuid->timeLow,
		uuid->timeMid,
		uuid->timeHiAndVersion,
		uuid->clockSeqAndNode[0],
		uuid->clockSeqAndNode[1],
		uuid->clockSeqAndNode[2],
		uuid->clockSeqAndNode[3],
		uuid->clockSeqAndNode[4],
		uuid->clockSeqAndNode[5],
		uuid->clockSeqAndNode[6],
		uuid->clockSeqAndNode[7]);
}

/*
 * This function is called by the TEE Client API whenever an OCALL arrives from
 * the TA.
 *
 * The 'taUUID' parameter carries the UUID of the TA that sent the OCALL. Since
 * a TA can open a session to another TA, it is possible to receive OCALLs from
 * other TAs that your TA calls into, if any.
 *
 * The 'commandId' indicates which function the TA wishes the CA to run.
 *
 * 'ctxData' is the arbitrary pointer that was set via the TEE context OCALL
 * setting, if any. Similarly, 'sessionData' is the arbitrary pointer set via
 * the session data setting, if it was supplied, or NULL.
 */
TEEC_Result ocall_handler(TEEC_UUID *taUUID, uint32_t commandId,
			  uint32_t paramTypes,
			  TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT],
			  void *ctxData, void *sessionData)
{
	const char *msg = "This string was sent by the CA";
	uint32_t expected_pt;

	printf("Received an OCALL for Command Id: %u\n", commandId);
	printf("The TA that sent it is: ");
	print_uuid(taUUID);
	printf("\n");

	switch (commandId) {
	case CA_OCALL_CMD_REPLY_SESSION_OPEN:
		expected_pt = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
					       TEEC_NONE,
					       TEEC_NONE,
					       TEEC_MEMREF_TEMP_INPUT);
		if (paramTypes != expected_pt) {
			fprintf(stderr, "Bad parameter types\n");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
		if (!params[3].tmpref.buffer) {
			fprintf(stderr, "No buffer\n");
			return TEEC_ERROR_BAD_PARAMETERS;
		}

		/* Print out the OCALL's INPUT/INOUT parameters */
		printf("Input values: 0x%x, 0x%x\n", params[0].value.a,
			params[0].value.b);
		printf("Input string: %s\n", (char *)params[3].tmpref.buffer);

		/* Set the OCALL's INOUT parameters */
		params[0].value.a = 0xCDDC1001;
		params[0].value.b = 0xFFFFCAFE;
		break;
	case CA_OCALL_CMD_REPLY_TA:
		expected_pt = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					       TEEC_VALUE_INOUT,
					       TEEC_MEMREF_TEMP_INPUT,
					       TEEC_MEMREF_TEMP_INOUT);
		if (paramTypes != expected_pt) {
			fprintf(stderr, "Bad parameter types\n");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
		if (!params[2].tmpref.buffer || !params[3].tmpref.buffer) {
			fprintf(stderr, "No buffer(s)\n");
			return TEEC_ERROR_BAD_PARAMETERS;
		}
		if (params[3].tmpref.size < strlen(msg) + 1) {
			fprintf(stderr, "Bad parameters\n");
			return TEEC_ERROR_BAD_PARAMETERS;
		}

		/* Print out the OCALL's INPUT/INOUT parameters */
		printf("Input values: %u, %u\n", params[0].value.a,
			params[0].value.b);
		printf("Inout values: %u, %u\n", params[1].value.a,
			params[1].value.b);

		printf("Input string: %s\n", (char *)params[2].tmpref.buffer);
		printf("Input size: %zu\n", params[2].tmpref.size);

		printf("Inout string: %s\n", (char *)params[3].tmpref.buffer);
		printf("Inout size: %zu\n", params[3].tmpref.size);

		/* Set the OCALL's INOUT parameters */
		params[1].value.a = 0x3;
		params[1].value.b = 0x4;

		params[3].tmpref.size = strlen(msg) + 1;
		memcpy(params[3].tmpref.buffer, msg, params[3].tmpref.size);
		break;
	default:
		fprintf(stderr, "Bad function ID\n");
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	printf("OCALL handled\n");
	return TEEC_SUCCESS;
}

int main(int argc, char* argv[])
{
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_OCALL_UUID;
	TEEC_Operation op;

	TEEC_Result res;
	uint32_t err_origin;

 	char buf[128];
 	char buf2[128];
	char *msg1 = "This string was sent by the CA";
	const char *msg2 = "The CA thinks this is a fun riddle";

	/*
	 * The TEE context OCALL setting allows specifying the callback handler
	 * for when an OCALL arrives from the TA. This handler is effectively
	 * the equivalent of TA_InvokeCommandEntryPoint, but on the CA side.
	 * Additionally, one may set an arbitrary pointer that will be passed
	 * to the OCALL handler when invoked.
	 *
	 * NOTE: You must pass this setting to the TEE context initialization
	 *       routine to receive OCALLs; otherwise, all OCALLs will return
	 *       a failure code.
	 */
	TEEC_ContextSettingOCall ocall_setting = {
		.handler = ocall_handler,
		.data = &ctx,
	};

	/* Array of TEE context settings */
	TEEC_ContextSetting ctx_settings = {
		.type = TEEC_CONTEXT_SETTING_OCALL,
		.u.ocall = &ocall_setting,
	};

	/* Initialize a TEE context with settings */
	res = TEEC_InitializeContext2(NULL, &ctx, &ctx_settings, 1);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * The session data setting allows attaching an arbitrary pointer to the
	 * session. This pointer will be passed to the OCALL handler when
	 * invoked.
	 *
	 * NOTE: This is optional; you can use TEEC_OpenSession as well even if
	 *       you expect OCALLs.
	 */
	TEEC_SessionSettingData data_setting = {
		.data = &sess
	};

	/* Array of session settings */
	TEEC_SessionSetting session_settings = {
		.type = TEEC_SESSION_SETTING_DATA,
		.u.data = &data_setting,
	};

	/* Set up the parameters for the TA's session open handler */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_NONE,
		TEEC_NONE);

	op.params[0].value.a = 0x0000CAFE;
	op.params[0].value.b = 0xCAFE0000;

	op.params[1].tmpref.buffer = (void *)msg2;
	op.params[1].tmpref.size = strlen(msg2) + 1;

	/* Open a session with settings; the sample TA will issue an OCALL */
	res = TEEC_OpenSession2(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
				&op, &err_origin, &session_settings, 1);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSessionEx failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*
	 * The code below executes after the OCALL has been handled in the
	 * callback at the top of this file.
	 */

	/*
	 * Set up the parameters for the function invocation. These are just to
	 * show that the CA can pass parameters to the TA and that during the
	 * function invocation that carries those parameters to the TA, the TA
	 * can make an OCALL with parameters of its own choosing. That is, the
	 * parameters passed from the CA to the TA do not interfere with those
	 * passed from the TA to the CA, and vice-versa.
	 */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT,
		TEEC_VALUE_INOUT,
		TEEC_MEMREF_TEMP_INPUT,
		TEEC_MEMREF_TEMP_INOUT);

	op.params[0].value.a = 0x3;
	op.params[0].value.b = 0x4;

	op.params[1].value.a = 0x5;
	op.params[1].value.b = 0x6;

	op.params[2].tmpref.buffer = msg1;
	op.params[2].tmpref.size = strlen(msg1) + 1;

	op.params[3].tmpref.buffer = buf;
	op.params[3].tmpref.size = sizeof(buf);
	memcpy(buf, msg2, strlen(msg2) + 1);

	/* Ask the TA to call us back */
	res = TEEC_InvokeCommand(&sess, TA_OCALL_CMD_CALL_CA, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*
	 * The code below once again executes after the OCALL has been handled
	 * in the callback at the top of this file.
	 */

	/*
	 * Print out the values of the INOUT parameters of the original function
	 * invocation that we got from the TA..
	 */
	printf("INOUT parameters from the original function invocation:\n");
	printf("Inout values: %u, %u\n", op.params[1].value.a,
	       op.params[1].value.b);

	printf("Inout string: %s\n", (char *)op.params[3].tmpref.buffer);
	printf("Inout size: %zu\n", op.params[3].tmpref.size);

	/* All done */
	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
