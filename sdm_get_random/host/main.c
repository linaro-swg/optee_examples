// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024-2026, Intel Corporation
 */

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include <sdm_get_random_ta.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s <size> [output_file]\n"
		"\n"
		"  size        hex (0x..) or decimal byte count\n"
		"              must be 4-aligned, %u..%u\n"
		"  output_file optional; writes raw bytes to file\n"
		"              (default: print hex to stdout)\n",
		prog, SDM_RNG_MIN_BYTES, SDM_RNG_MAX_BYTES);
	exit(1);
}

int main(int argc, char *argv[])
{
	TEEC_Result res = 0;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_SharedMemory out_shm = { };
	TEEC_UUID uuid = TA_SDM_GET_RANDOM_UUID;
	uint32_t err_origin = 0;
	unsigned long size_arg = 0;
	uint32_t size = 0;
	uint32_t returned = 0;
	uint8_t *buf = NULL;
	const char *out_path = NULL;

	if (argc < 2 || argc > 3)
		usage(argv[0]);

	size_arg = strtoul(argv[1], NULL, 0);
	if (size_arg < SDM_RNG_MIN_BYTES || size_arg > SDM_RNG_MAX_BYTES ||
	    (size_arg % 4) != 0)
		errx(1, "size %lu invalid: must be 4-aligned, %u..%u",
		     size_arg, SDM_RNG_MIN_BYTES, SDM_RNG_MAX_BYTES);

	size = (uint32_t)size_arg;
	if (argc == 3)
		out_path = argv[2];

	buf = calloc(1, size);
	if (!buf)
		err(1, "calloc");

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext: 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession: 0x%x (origin 0x%x)",
		     res, err_origin);

	out_shm.buffer = buf;
	out_shm.size   = size;
	out_shm.flags  = TEEC_MEM_OUTPUT;
	res = TEEC_RegisterSharedMemory(&ctx, &out_shm);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory: 0x%x", res);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_WHOLE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a       = size;
	op.params[1].memref.parent = &out_shm;
	op.params[1].memref.size   = size;

	res = TEEC_InvokeCommand(&sess, TA_SDM_GET_RANDOM_CMD_GET, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TA_SDM_GET_RANDOM_CMD_GET: 0x%x (origin 0x%x)",
		     res, err_origin);

	returned = (uint32_t)op.params[1].memref.size;

	if (out_path) {
		FILE *fp = fopen(out_path, "wb");

		if (!fp)
			err(1, "open %s for write", out_path);
		if (fwrite(buf, 1, returned, fp) != returned)
			err(1, "fwrite %s", out_path);
		fclose(fp);
		printf("sdm_get_random: %u bytes written to %s\n",
		       returned, out_path);
	} else {
		for (uint32_t i = 0; i < returned; i++) {
			printf("%02x", buf[i]);
			if ((i + 1) % 32 == 0 || i + 1 == returned)
				printf("\n");
			else if ((i + 1) % 4 == 0)
				printf(" ");
		}
	}

	TEEC_ReleaseSharedMemory(&out_shm);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	free(buf);

	return 0;
}
