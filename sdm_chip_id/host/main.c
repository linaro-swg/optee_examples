// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024-2026, Intel Corporation
 */

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <sdm_chip_id_ta.h>

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SDM_CHIP_ID_UUID;
	uint32_t err_origin;
	uint64_t chip_id;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed: 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed: 0x%x (origin 0x%x)",
		     res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, TA_SDM_CHIP_ID_CMD_GET, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed: 0x%x (origin 0x%x)",
		     res, err_origin);

	chip_id = ((uint64_t)op.params[0].value.b << 32) |
		   (uint64_t)op.params[0].value.a;

	printf("SDM Chip ID: 0x%016" PRIx64 "\n", chip_id);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
