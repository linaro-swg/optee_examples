// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <sha_ta.h>

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint32_t algo_num;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_SHA_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

static void usage(int argc, char *argv[])
{
	const char *pname = "optee_example_sha";

	if (argc)
		pname = argv[0];

	fprintf(stderr, "%s: %s <string to encrypt> <algo name>\n",
		__func__, pname);
	printf("SUPPORTED ALGORITHMS:\n");
	printf("TA_ALGO_HMAC_SHA1\n");
	printf("TA_ALGO_HMAC_SHA224\n");
	printf("TA_ALGO_HMAC_SHA256\n");
	printf("TA_ALGO_HMAC_SHA384\n");
	printf("TA_ALGO_HMAC_SHA512\n");
	exit(1);
}

void prepare_hmac_sha(struct test_ctx *ctx, size_t key_size, uint32_t obj_type)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = ctx->algo_num;
	op.params[1].value.a = key_size;
	op.params[2].value.a = obj_type;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_PREPARE,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
}

void set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_SET_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}

void sha_update_ops(struct test_ctx *ctx, void *message, size_t message_sz,
		    void *hmac_buff, size_t *hmac_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = message_sz;
	op.params[1].tmpref.buffer = hmac_buff;
	op.params[1].tmpref.size = *hmac_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_CMD_SHA_INIT, &op,
				 &origin);
	if (res == TEEC_SUCCESS)
		*hmac_sz = op.params[1].tmpref.size;
	else
		errx(1, "TEEC_InvokeCommand(SHA_OPS) failed 0x%x origin 0x%x",
		     res, origin);
}

TEEC_Result compare_hmac_sha(struct test_ctx *ctx, void *message, size_t message_sz,
		      void *hmac_buff, size_t *hmac_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = message_sz;
	op.params[1].tmpref.buffer = hmac_buff;
	op.params[1].tmpref.size = *hmac_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_CMD_SHA_CMPR, &op,
				 &origin);

	return res;
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx;
	size_t key_size;
	void *message;
	size_t message_sz;
	char hmac_buff[64];
	size_t hmac_sz = sizeof(hmac_buff);
	char *algo;
	uint32_t obj_type;
	TEEC_Result res;

	if ((argc < 2) || (argc > 3)) {
		warnx("Unexpected number of arguments %d (expected 2)",
		      argc - 1);
		usage(argc, argv);
	}

	message = argv[1];
	message_sz = strlen(argv[1]);

	if (argc > 2) {
		algo = argv[2];
		printf("%s algo selected\n", algo);
		if (strcmp(algo, "TA_ALGO_HMAC_SHA256") == 0) {
			ctx.algo_num = TA_ALGO_HMAC_SHA256;
			obj_type = TA_TYPE_HMAC_SHA256;
			key_size = 128; /* 128 bytes */
		} else if (strcmp(algo, "TA_ALGO_HMAC_SHA1") == 0) {
			ctx.algo_num = TA_ALGO_HMAC_SHA1;
			obj_type = TA_TYPE_HMAC_SHA1;
			key_size = 64; /* 64 bytes */
		} else if (strcmp(algo, "TA_ALGO_HMAC_SHA224") == 0) {
			ctx.algo_num = TA_ALGO_HMAC_SHA224;
			obj_type = TA_TYPE_HMAC_SHA224;
			key_size = 64; /* 64 bytes */
		} else if (strcmp(algo, "TA_ALGO_HMAC_SHA384") == 0) {
			ctx.algo_num = TA_ALGO_HMAC_SHA384;
			obj_type = TA_TYPE_HMAC_SHA384;
			key_size = 128; /* 128 bytes */
		} else if (strcmp(algo, "TA_ALGO_HMAC_SHA512") == 0) {
			ctx.algo_num = TA_ALGO_HMAC_SHA512;
			obj_type = TA_TYPE_HMAC_SHA512;
			key_size = 128; /* 128 bytes */
		} else {
			printf("%s algo is invalid\n", algo);
			return -1;
		}
	} else {
		printf("TA_ALGO_HMAC_SHA256 algo selected\n");
		ctx.algo_num = TA_ALGO_HMAC_SHA256;
		obj_type = TA_TYPE_HMAC_SHA256;
		key_size = 128; /* 128 bytes */
	}

	char key[key_size];

	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	printf("Prepare SHA compute operation\n");
	prepare_hmac_sha(&ctx, key_size, obj_type);

	printf("Load key in TA\n");
	memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	set_key(&ctx, key, key_size);

	printf("Reset operation in TA (provides the initial vector)\n");
	set_iv(&ctx, NULL, 0);

	printf("Compute SHA operation\n");
	sha_update_ops(&ctx, message, message_sz, (void *)hmac_buff,
		       &hmac_sz);

	printf("Prepare SHA compare operation\n");
	prepare_hmac_sha(&ctx, key_size, obj_type);

	printf("Load key in TA\n");
	memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	set_key(&ctx, key, key_size);

	printf("Reset operation in TA (provides the initial vector)\n");
	set_iv(&ctx, NULL, 0);

	printf("Compare the MAC\n");
	res = compare_hmac_sha(&ctx, message, message_sz,
			       (void *)hmac_buff, &hmac_sz);

	if (res == TEEC_SUCCESS)
		printf("MAC successfully matching\n");
	else
		printf("SHA did not match\n");

	printf("MAC: ");
	for (int32_t i = 0 ; i < hmac_sz ; i++)
		printf("%02x", hmac_buff[i]);

	printf("\n");

	terminate_tee_session(&ctx);
	return 0;
}
