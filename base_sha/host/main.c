// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>

#include <base_sha_ta.h>

struct base_sha_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint32_t selected_algo;
};

static void usage(int argc, char *argv[])
{
	const char *pname = "base_sha";

	if (argc)
		pname = argv[0];

	fprintf(stderr, "%s: %s <string to encrypt> <algo name>\n",
		__func__, pname);
	printf("SUPPORTED ALGORITHMS:\n");
	printf("SHA1 - TA_ALG_SHA1\n");
	printf("SHA224 - TA_ALG_SHA224\n");
	printf("SHA256 - TA_ALG_SHA256\n");
	printf("SHA384 - TA_ALG_SHA384\n");
	printf("SHA512 - TA_ALG_SHA512\n");
	printf("SHA3_224 - TA_ALG_SHA3_224\n");
	printf("SHA3_256 - TA_ALG_SHA3_256\n");
	printf("SHA3_384 - TA_ALG_SHA3_384\n");
	printf("SHA3_512 - TA_ALG_SHA3_512\n");
	printf("SHAKE128 - TA_ALG_SHAKE128\n");
	printf("SHAKE256 - TA_ALG_SHAKE256\n");
	exit(1);
}

static void get_args(int argc, char *argv[], void **msg, size_t *msg_len,
		     uint32_t *algo_num)
{
	char *algo;

	if ((argc < 2) || (argc > 3)) {
		warnx("Unexpected number of arguments %d (expected 2)",
		      argc - 1);
		usage(argc, argv);
	}

	*msg = argv[1];
	*msg_len = strlen(argv[1]);

	if (argc > 2) {
		algo = argv[2];
		printf("%s algo selected\n", algo);
		if (strcmp(algo, "TA_ALG_SHA1") == 0) {
			*algo_num = TA_ALG_SHA1;
		} else if (strcmp(algo, "TA_ALG_SHA224") == 0) {
			*algo_num = TA_ALG_SHA224;
		} else if (strcmp(algo, "TA_ALG_SHA256") == 0) {
			*algo_num = TA_ALG_SHA256;
		} else if (strcmp(algo, "TA_ALG_SHA384") == 0) {
			*algo_num = TA_ALG_SHA384;
		} else if (strcmp(algo, "TA_ALG_SHA512") == 0) {
			*algo_num = TA_ALG_SHA512;
		} else if (strcmp(algo, "TA_ALG_SHA3_224") == 0) {
			*algo_num = TA_ALG_SHA3_224;
		} else if (strcmp(algo, "TA_ALG_SHA3_256") == 0) {
			*algo_num = TA_ALG_SHA3_256;
		} else if (strcmp(algo, "TA_ALG_SHA3_384") == 0) {
			*algo_num = TA_ALG_SHA3_384;
		} else if (strcmp(algo, "TA_ALG_SHA3_512") == 0) {
			*algo_num = TA_ALG_SHA3_512;
		} else if (strcmp(algo, "TA_ALG_SHAKE128") == 0) {
			*algo_num = TA_ALG_SHAKE128;
		} else if (strcmp(algo, "TA_ALG_SHAKE256") == 0) {
			*algo_num = TA_ALG_SHAKE256;
		} else {
			printf("%s algo is invalid\n", algo);
			usage(argc, argv);
		}
	} else {
		printf("TA_ALG_SHA256 algo selected\n");
		*algo_num = TA_ALG_SHA256;
	}
}

void compute_digest(struct base_sha_ctx *ctx, void *message, size_t msg_len,
		    void *digest, size_t *digest_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);
	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = msg_len;
	op.params[1].tmpref.buffer = digest;
	op.params[1].tmpref.size = *digest_len;
	op.params[2].value.a = ctx->selected_algo;

	res = TEEC_InvokeCommand(&ctx->sess, CMD_COMPUTE_DIGEST, &op,
				 &origin);
	if (res == TEEC_SUCCESS) {
		*digest_len = op.params[1].tmpref.size;
	} else {
		errx(1, "TEEC_InvokeCommand(COMPUTE DIGEST) failed 0x%x origin 0x%x",
		     res, origin);
	}
}

void prepare_tee_session(struct base_sha_ctx *ctx)
{
	TEEC_UUID uuid = TA_BASE_SHA_UUID;
	uint32_t origin;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		     res, origin);
}

void terminate_tee_session(struct base_sha_ctx *sess)
{
	TEEC_CloseSession(&sess->sess);
	TEEC_FinalizeContext(&sess->ctx);
}

int main(int argc, char *argv[])
{
	struct base_sha_ctx ctx;
	void *msg;
	size_t msg_len;
	uint8_t digest[64];
	size_t digest_len = sizeof(digest);

	printf("Getting arg\n");
	get_args(argc, argv, &msg, &msg_len, &ctx.selected_algo);

	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	printf("Compute digest\n");
	compute_digest(&ctx, msg, msg_len, (void *)digest, &digest_len);

	printf("digest:");
	for (size_t i = 0; i < digest_len; i++)
		printf("%02x ", digest[i]);
	printf("\n");

	terminate_tee_session(&ctx);
	return 0;
}
