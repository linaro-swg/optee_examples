// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>

#include <ecdh_ta.h>

static void hexdump(const void *p, size_t len)
{
	const unsigned char *b = (const unsigned char *)p;

	for (size_t i = 0; i < len; i++) {
		printf("%02x", b[i]);
		if ((i + 1) % 32 == 0)
			printf("\n");
	}
	if (len % 32)
		printf("\n");
}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_ECDH_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed 0x%x origin 0x%x",
		     res, err_origin);

	uint32_t curve = TA_ECC_CURVE_NIST_P384;

	uint8_t secret[ECDH_BUF_BYTES];

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
					 TEEC_NONE,
					 TEEC_NONE,
					 TEEC_MEMREF_TEMP_OUTPUT);

	op.params[0].value.a = curve;        /* IN: curve id */
	op.params[0].value.b = 0;            /* OUT: secret len */
	op.params[3].tmpref.buffer = secret; /* OUT buffer for secret */
	op.params[3].tmpref.size = sizeof(secret);

	res = TEEC_InvokeCommand(&sess, TA_ECDH_CMD_DERIVE_SELFTEST,
				 &op, &err_origin);
	if (res == TEEC_ERROR_SHORT_BUFFER) {
		/* Resize and try once more with the exact size TA asked for */
		size_t need = op.params[0].value.b;

		if (need > sizeof(secret))
			errx(1, "Required secret buffer too big: %zu", need);

		op.params[3].tmpref.size = need;
		res = TEEC_InvokeCommand(&sess, TA_ECDH_CMD_DERIVE_SELFTEST,
					 &op, &err_origin);
	}

	if (res != TEEC_SUCCESS)
		errx(1, "Invoke TA_ECDH_CMD_DERIVE_SELFTEST failed 0x%x origin 0x%x",
		     res, err_origin);

	size_t secret_len = op.params[0].value.b;

	printf("ECDH shared secret (%zu bytes) on curve id %u:\n",
	       secret_len, curve);
	hexdump(secret, secret_len);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
