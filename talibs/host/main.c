// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <err.h>
#include <tee_client_api.h>
#include <libs_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_LIBS_EXAMPLE_UUID;
	uint32_t err_origin;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "library example" TA, the TA will invoke
	 * functions implemented in libraries (libtalib1.a, libtalib2.so,
	 * libtalib3.so). Watch the secure console for debug messages from the
	 * libraries.
	 * We expect a failure because the TA should call TEE_Panic().
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_ERROR_TARGET_DEAD)
		errx(1, "TEEC_Opensession failed unexpectedly with code 0x%x "
			"origin 0x%x", res, err_origin);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
