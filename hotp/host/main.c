/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <hotp_ta.h>

struct test_value {
	size_t count;
	uint32_t expected;
};

/*
 * Test values coming from the RFC4226 specification.
 */
struct test_value rfc4226_test_values[] = {
	{ 0, 755224 },
	{ 1, 287082 },
	{ 2, 359152 },
	{ 3, 969429 },
	{ 4, 338314 },
	{ 5, 254676 },
	{ 6, 287922 },
	{ 7, 162583 },
	{ 8, 399871 },
	{ 9, 520489 }
};

int main(void)
{
	TEEC_Context ctx;
	TEEC_Operation op = { 0 };
	TEEC_Result res;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_HOTP_UUID;

	size_t i;
	uint32_t err_origin;
	uint32_t hotp_value;

	/*
	 * Shared key K ("12345678901234567890"), this is the key used in
	 * RFC4226 - Test Vectors.
	 */
	uint8_t K[] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
		0x37, 0x38, 0x39, 0x30
	};

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		     res, err_origin);

	/* 1. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = K;
	op.params[0].tmpref.size = sizeof(K);

	fprintf(stdout, "Register the shared key: %s\n", K);
	res = TEEC_InvokeCommand(&sess, TA_HOTP_CMD_REGISTER_SHARED_KEY,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_InvokeCommand failed with code 0x%x "
			"origin 0x%x\n",
			res, err_origin);
		goto exit;
	}

	/* 2. Get HMAC based One Time Passwords */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	for (i = 0; i < sizeof(rfc4226_test_values) / sizeof(struct test_value);
	     i++) {
		res = TEEC_InvokeCommand(&sess, TA_HOTP_CMD_GET_HOTP, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS) {
			fprintf(stderr, "TEEC_InvokeCommand failed with code "
				"0x%x origin 0x%x\n", res, err_origin);
			goto exit;
		}

		hotp_value = op.params[0].value.a;
		fprintf(stdout, "HOTP: %d\n", hotp_value);

		if (hotp_value != rfc4226_test_values[i].expected) {
			fprintf(stderr, "Got unexpected HOTP from TEE! "
				"Expected: %d, got: %d\n",
				rfc4226_test_values[i].expected, hotp_value);
		}
	}
exit:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
