// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include <sdm_fuse_read_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res = 0;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_SharedMemory out_shm = { };
	TEEC_UUID uuid = TA_SDM_FUSE_READ_UUID;
	uint32_t err_origin = 0;
	uint32_t fuse_data[SDM_USER_FUSE_COUNT] = { };
	unsigned int i = 0;
	int exit_code = 1;

	if (argc != 1) {
		fprintf(stderr,
			"Usage: %s\n\n"
			"Read and display all 16 SDM user-defined eFuse words.\n",
			argv[0]);
		return 1;
	}

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext: 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_OpenSession: 0x%x (origin 0x%x)\n",
			res, err_origin);
		goto out_ctx;
	}

	out_shm.buffer = fuse_data;
	out_shm.size   = SDM_USER_FUSE_SIZE;
	out_shm.flags  = TEEC_MEM_OUTPUT;
	res = TEEC_RegisterSharedMemory(&ctx, &out_shm);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_RegisterSharedMemory: 0x%x\n", res);
		goto out_sess;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = &out_shm;
	op.params[0].memref.size   = SDM_USER_FUSE_SIZE;

	res = TEEC_InvokeCommand(&sess, TA_SDM_FUSE_READ_CMD_GET,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr,
			"TA_SDM_FUSE_READ_CMD_GET: 0x%x (origin 0x%x)\n",
			res, err_origin);
		goto out_shm;
	}

	printf("\nSDM User eFuse Data (%u words):\n\n", SDM_USER_FUSE_COUNT);
	for (i = 0; i < SDM_USER_FUSE_COUNT; i++)
		printf("  Word %2u: 0x%08" PRIX32 "\n", i, fuse_data[i]);
	printf("\n");

	exit_code = 0;

out_shm:
	TEEC_ReleaseSharedMemory(&out_shm);
out_sess:
	TEEC_CloseSession(&sess);
out_ctx:
	TEEC_FinalizeContext(&ctx);
	return exit_code;
}
