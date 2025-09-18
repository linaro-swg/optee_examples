// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <aes_ta.h>

#define AES_TEST_BUFFER_SIZE	4096
#define AES_TEST_KEY_SIZE	16
#define AES_BLOCK_SIZE		16

#define DECODE			0
#define ENCODE			1

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint32_t algo_num;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_AES_UUID;
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

void prepare_aes(struct test_ctx *ctx, int encode)
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
	op.params[1].value.a = TA_AES_SIZE_128BIT;
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE :
					TA_AES_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
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

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
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

	if (ctx->algo_num == TA_AES_ALGO_ECB) {
		iv = NULL;
		iv_sz = 0;
	}

	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}

void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			res, origin);
}

void auth_enc_op(struct test_ctx *ctx, uint32_t encrypt, void *in_buf, size_t
		  in_sz, void *out_buf, size_t *out_sz, void *tag, size_t
		  *tag_len)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t err_origin;

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INOUT);
	op.params[0].tmpref.buffer = in_buf;
	op.params[0].tmpref.size = in_sz;

	op.params[1].tmpref.buffer = out_buf;
	op.params[1].tmpref.size = *out_sz;

	op.params[2].value.a = encrypt;

	op.params[3].tmpref.buffer = tag;
	op.params[3].tmpref.size = *tag_len;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_AUTHENC,
				 &op, &err_origin);

	if (res == TEEC_SUCCESS) {
		*out_sz = op.params[1].tmpref.size;
		*tag_len = op.params[3].tmpref.size;
	} else {
		errx(1, "InvokeCommand failed with %x\n", res);
	}
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx;
	char key[AES_TEST_KEY_SIZE];
	char iv[AES_BLOCK_SIZE];
	char clear[AES_TEST_BUFFER_SIZE];
	char ciph[AES_TEST_BUFFER_SIZE];
	char temp[AES_TEST_BUFFER_SIZE];
	char *algo;
	char plaintext[] = "TestCCMMessage";
	uint8_t ciphertext[80] = {0};
	uint8_t decrypted[80] = {0};
	size_t ct_len = sizeof(ciphertext);
	size_t dec_len = sizeof(decrypted);
	uint8_t tag[16] = {0};
	size_t tag_len = 16;

	if (argc > 1) {
		algo = argv[1];
		printf("%s algo selected\n", algo);
		if (strcmp(algo, "TA_AES_ALGO_ECB") == 0) {
			ctx.algo_num = TA_AES_ALGO_ECB;
		} else if (strcmp(algo, "TA_AES_ALGO_CBC") == 0) {
			ctx.algo_num = TA_AES_ALGO_CBC;
		} else if (strcmp(algo, "TA_AES_ALGO_CTR") == 0) {
			ctx.algo_num = TA_AES_ALGO_CTR;
		} else if (strcmp(algo, "TA_AES_ALGO_CCM") == 0) {
			ctx.algo_num = TA_AES_ALGO_CCM;
		} else if (strcmp(algo, "TA_AES_ALGO_GCM") == 0) {
			ctx.algo_num = TA_AES_ALGO_GCM;
		} else {
			printf("%s algo is invalid\n", algo);
			return -1;
		}
	} else {
		printf("TA_AES_ALGO_CTR algo selected\n");
		ctx.algo_num = TA_AES_ALGO_CTR;
	}

	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	printf("Prepare encode operation\n");
	prepare_aes(&ctx, ENCODE);

	printf("Load key in TA\n");
	memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	set_key(&ctx, key, AES_TEST_KEY_SIZE);

	if ((ctx.algo_num == TA_AES_ALGO_CCM) || (ctx.algo_num == TA_AES_ALGO_GCM)) {
		printf("AE encode operation in TA\n");
		auth_enc_op(&ctx, TA_AES_MODE_ENCODE, plaintext,
			    strlen(plaintext),  ciphertext, &ct_len,
			    tag, &tag_len);
	} else {
		printf("Reset ciphering operation in TA (provides the initial vector)\n");
		memset(iv, 0, sizeof(iv)); /* Load some dummy value */
		set_iv(&ctx, iv, AES_BLOCK_SIZE);
		printf("Encode buffer from TA\n");
		memset(clear, 0x5a, sizeof(clear)); /* Load some dummy value */
		cipher_buffer(&ctx, clear, ciph, AES_TEST_BUFFER_SIZE);
	}

	printf("Prepare decode operation\n");
	prepare_aes(&ctx, DECODE);

	printf("Load key in TA\n");
	memset(key, 0xa5, sizeof(key)); /* Load some dummy value */
	set_key(&ctx, key, AES_TEST_KEY_SIZE);

	if ((ctx.algo_num == TA_AES_ALGO_CCM) || (ctx.algo_num == TA_AES_ALGO_GCM)) {
		printf("AE decode operation in TA\n");
		auth_enc_op(&ctx, TA_AES_MODE_DECODE, ciphertext, ct_len, decrypted,
			     &dec_len, tag, &tag_len);
	} else {
		printf("Reset ciphering operation in TA (provides the initial vector)\n");
		memset(iv, 0, sizeof(iv)); /* Load some dummy value */
		set_iv(&ctx, iv, AES_BLOCK_SIZE);
		printf("Decode buffer from TA\n");
		cipher_buffer(&ctx, ciph, temp, AES_TEST_BUFFER_SIZE);
	}

	/* Check decoded is the clear content */
	if ((ctx.algo_num == TA_AES_ALGO_CCM) || (ctx.algo_num == TA_AES_ALGO_GCM)) {
		if (memcmp(plaintext, decrypted, strlen(plaintext)) == 0)
			printf("CCM encryption/decryption successful!\n");
		else
			printf("Decryption failed or tag mismatch!\n");

	} else {
		if (memcmp(clear, temp, AES_TEST_BUFFER_SIZE))
			printf("Clear text and decoded text differ => ERROR\n");
		else
			printf("Clear text and decoded text match\n");
	}

	terminate_tee_session(&ctx);
	return 0;
}
