// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <sha_ta.h>

/* Algo Type */
#define SHA_HMAC	0
#define BASE_SHA        1

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint32_t algo_num;
};

static void prepare_tee_session(struct test_ctx *ctx)
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

static void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

static void usage(int argc, char *argv[])
{
	fprintf(stderr, "Usage: %s <string to process> [<algo>]\n\n", argv[0]);
	fprintf(stderr, "Example of hash, HMAC and CMAC in a TA.\n\n");
	fprintf(stderr, "<algo>    Optional algorithm name. HMAC_SHA256 if omitted.\n");
	fprintf(stderr, "          Supported values are:\n");
	fprintf(stderr, "          HMAC_SHA1, HMAC_SHA224, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512\n");
	fprintf(stderr, "          AES_CMAC\n");
	fprintf(stderr, "          SHA1, SHA224, SHA256, SHA384, SHA512\n");
	fprintf(stderr, "          SHA3_224, SHA3_256, SHA3_384, SHA3_512\n");
	fprintf(stderr, "          SHAKE128, SHAKE256\n");
	exit(1);
}

static void compute_digest(struct test_ctx *ctx, void *message, size_t msg_len,
		    void *digest, size_t *digest_len)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = msg_len;
	op.params[1].tmpref.buffer = digest;
	op.params[1].tmpref.size = *digest_len;
	op.params[2].value.a = ctx->algo_num;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_COMPUTE_DIGEST, &op,
				 &origin);

	*digest_len = op.params[1].tmpref.size;

	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand(COMPUTE DIGEST) failed 0x%x origin 0x%x",
		     res, origin);
	}
}

static void prepare_hmac_sha(struct test_ctx *ctx, size_t key_size,
		      enum ta_sha_object_type obj_type)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = ctx->algo_num;
	op.params[1].value.a = key_size;
	op.params[2].value.a = (uint32_t)obj_type;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_PREPARE,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
}

static void set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

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

static void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

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

static void sha_update_ops(struct test_ctx *ctx, void *message, size_t message_sz,
		    void *hmac_buff, size_t *hmac_sz)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = message_sz;
	op.params[1].tmpref.buffer = hmac_buff;
	op.params[1].tmpref.size = *hmac_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_COMPUTE_MAC, &op,
				 &origin);

	*hmac_sz = op.params[1].tmpref.size;

	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand(SHA_OPS) failed 0x%x origin 0x%x",
		     res, origin);
	}
}

static TEEC_Result compare_hmac_sha(struct test_ctx *ctx, void *message,
				    size_t message_sz, void *hmac_buff,
				    size_t *hmac_sz)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = message_sz;
	op.params[1].tmpref.buffer = hmac_buff;
	op.params[1].tmpref.size = *hmac_sz;

	return TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_COMPARE_MAC, &op,
				  &origin);
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx = {0};
	size_t key_size;
	void *message = NULL;
	size_t message_sz = 0;
	char buff[64] = {0};
	size_t buff_sz = sizeof(buff);
	char *algo = NULL;
	enum ta_sha_object_type obj_type;
	uint32_t algo_type;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	if (argc < 2 || argc > 3) {
		warnx("Unexpected number of arguments %d (expected 2)\n",
		      argc - 1);
		usage(argc, argv);
	}

	message = argv[1];
	message_sz = strlen(argv[1]);

	if (argc > 2) {
		algo = argv[2];
		printf("%s algo selected\n", algo);
		if (strcmp(algo, "HMAC_SHA256") == 0) {
			ctx.algo_num = TEE_ALG_HMAC_SHA256;
			obj_type = TA_SHA_OBJ_TYPE_HMAC_SHA256;
			key_size = 128; /* 128 bytes */
			algo_type = SHA_HMAC;
		} else if (strcmp(algo, "HMAC_SHA1") == 0) {
			ctx.algo_num = TEE_ALG_HMAC_SHA1;
			obj_type = TA_SHA_OBJ_TYPE_HMAC_SHA1;
			key_size = 64; /* 64 bytes */
			algo_type = SHA_HMAC;
		} else if (strcmp(algo, "HMAC_SHA224") == 0) {
			ctx.algo_num = TEE_ALG_HMAC_SHA224;
			obj_type = TA_SHA_OBJ_TYPE_HMAC_SHA224;
			key_size = 64; /* 64 bytes */
			algo_type = SHA_HMAC;
		} else if (strcmp(algo, "HMAC_SHA384") == 0) {
			ctx.algo_num = TEE_ALG_HMAC_SHA384;
			obj_type = TA_SHA_OBJ_TYPE_HMAC_SHA384;
			key_size = 128; /* 128 bytes */
			algo_type = SHA_HMAC;
		} else if (strcmp(algo, "HMAC_SHA512") == 0) {
			ctx.algo_num = TEE_ALG_HMAC_SHA512;
			obj_type = TA_SHA_OBJ_TYPE_HMAC_SHA512;
			key_size = 128; /* 128 bytes */
			algo_type = SHA_HMAC;
		} else if (strcmp(algo, "AES_CMAC") == 0) {
			ctx.algo_num = TEE_ALG_AES_CMAC;
			obj_type = TA_SHA_OBJ_TYPE_AES;
			key_size = 16; /* 16 bytes */
			algo_type = SHA_HMAC;
		} else if (strcmp(algo, "SHA1") == 0) {
			ctx.algo_num = TEE_ALG_SHA1;
			algo_type = BASE_SHA;
		} else if (strcmp(algo, "SHA224") == 0) {
			ctx.algo_num = TEE_ALG_SHA224;
			algo_type = BASE_SHA;
		} else if (strcmp(algo, "SHA256") == 0) {
			ctx.algo_num = TEE_ALG_SHA256;
			algo_type = BASE_SHA;
		} else if (strcmp(algo, "SHA384") == 0) {
			ctx.algo_num = TEE_ALG_SHA384;
			algo_type = BASE_SHA;
		} else if (strcmp(algo, "SHA512") == 0) {
			ctx.algo_num = TEE_ALG_SHA512;
			algo_type = BASE_SHA;
		} else if (strcmp(algo, "SHA3_224") == 0) {
			ctx.algo_num = TEE_ALG_SHA3_224;
			algo_type = BASE_SHA;
		} else if (strcmp(algo, "SHA3_256") == 0) {
			ctx.algo_num = TEE_ALG_SHA3_256;
			algo_type = BASE_SHA;
		} else if (strcmp(algo, "SHA3_384") == 0) {
			ctx.algo_num = TEE_ALG_SHA3_384;
			algo_type = BASE_SHA;
		} else if (strcmp(algo, "SHA3_512") == 0) {
			ctx.algo_num = TEE_ALG_SHA3_512;
			algo_type = BASE_SHA;
		} else if (strcmp(algo, "SHAKE128") == 0) {
			ctx.algo_num = TEE_ALG_SHAKE128;
			algo_type = BASE_SHA;
		} else if (strcmp(algo, "SHAKE256") == 0) {
			ctx.algo_num = TEE_ALG_SHAKE256;
			algo_type = BASE_SHA;
		} else {
			printf("%s algo is invalid\n", algo);
			usage(argc, argv);
		}
	} else {
		printf("HMAC_SHA256 algo selected\n");
		ctx.algo_num = TEE_ALG_HMAC_SHA256;
		key_size = 128; /* 128 bytes */
		obj_type = TA_SHA_OBJ_TYPE_HMAC_SHA256;
		algo_type = SHA_HMAC;
	}

	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	if (algo_type != SHA_HMAC) {
		/* SHA digest */
		printf("Compute digest\n");
		compute_digest(&ctx, message, message_sz, (void *)buff,
			       &buff_sz);
		printf("digest: ");

	} else {
		/* SHA HMAC */
		char key[key_size];

		printf("Prepare MAC compute operation\n");
		prepare_hmac_sha(&ctx, key_size, obj_type);

		printf("Load key in TA\n");
		memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
		set_key(&ctx, key, key_size);

		printf("Reset operation in TA (provides the initial vector)\n");
		set_iv(&ctx, NULL, 0);

		printf("Compute MAC operation\n");
		sha_update_ops(&ctx, message, message_sz, (void *)buff,
			       &buff_sz);

		printf("Prepare MAC compare operation\n");
		prepare_hmac_sha(&ctx, key_size, obj_type);

		printf("Load key in TA\n");
		memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
		set_key(&ctx, key, key_size);

		printf("Reset operation in TA (provides the initial vector)\n");
		set_iv(&ctx, NULL, 0);

		printf("Compare the MAC\n");
		res = compare_hmac_sha(&ctx, message, message_sz,
				       (void *)buff, &buff_sz);

		if (res == TEEC_SUCCESS)
			printf("MAC successfully matching\n");
		else
			printf("MAC did not match\n");

		printf("MAC: ");
	}

	for (int32_t i = 0 ; i < buff_sz ; i++)
		printf("%02x", buff[i]);

	printf("\n");

	terminate_tee_session(&ctx);
	return 0;
}
