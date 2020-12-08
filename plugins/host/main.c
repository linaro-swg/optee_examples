// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <plugin_ta.h>

#define SLEEP_SEC 2
#define TA_PING_CNT 5

int main(void)
{
	int i = 0;
	TEEC_Result res = TEEC_SUCCESS;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_UUID uuid = PLUGIN_TA_UUID;
	uint32_t err_origin = 0;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code %#" PRIx32,
		     res);

	/* Open a session to the "plugin" TA */
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code %#" PRIx32 "origin %#" PRIx32,
		     res, err_origin);

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));
	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	/*
	 * TA will refer to the syslog plugin to print some log messages to REE.
	 *
	 * See the plugin code in the optee-client.
	 * See the log through 'journalctl'.
	 */

	printf("Work logic: REE --> plugin TA --> syslog plugin in REE --> syslog\n");
	printf("See the log from TEE through 'journalctl'\n\n");

	for (i = 0; i < TA_PING_CNT; ++i) {
		res = TEEC_InvokeCommand(&sess, PLUGIN_TA_PING, &op,
					 &err_origin);

		printf("Attempt #%d: TEEC_InvokeCommand() %s; res=%#" PRIx32 " orig=%#" PRIx32 "\n",
		       i + 1, (res == TEEC_SUCCESS) ? "success" : "failed",
		       res, err_origin);

		sleep(SLEEP_SEC);
	}

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 */

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
