// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>

#include <ecdsa_ta.h>

struct ecdsa_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint32_t selected_algo;
};

static void usage(const char *pname)
{
	fprintf(stderr, "usage: %s [<algo>]\n\n", pname);
	fprintf(stderr, "Example of ECSDSA authentication in a TA\n\n");
	fprintf(stderr, "<algo>     ECDSA algorithm to use, supported values:\n");
	fprintf(stderr, "           ECDSA_SHA1\n");
	fprintf(stderr, "           ECDSA_SHA224\n");
	fprintf(stderr, "           ECDSA_SHA256 (default)\n");
	fprintf(stderr, "           ECDSA_SHA384\n");
	fprintf(stderr, "           ECDSA_SHA512\n");
}

void prepare_tee_session(struct ecdsa_ctx *ctx)
{
	TEEC_UUID uuid = TA_ECDSA_UUID;
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

void terminate_tee_session(struct ecdsa_ctx *sess)
{
	TEEC_CloseSession(&sess->sess);
	TEEC_FinalizeContext(&sess->ctx);
}

void compute_digest(struct ecdsa_ctx *ctx, void *message, size_t msg_len,
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

	res = TEEC_InvokeCommand(&ctx->sess, TA_ECDSA_CMD_COMPUTE_DIGEST,
				 &op, &origin);
	if (res == TEEC_SUCCESS) {
		*digest_len = op.params[1].tmpref.size;
	} else {
		errx(1, "TEEC_InvokeCommand(COMPUTE DIGEST) failed 0x%x origin 0x%x",
		     res, origin);
	}

}

void genrate_key(struct ecdsa_ctx *ctx)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&ctx->sess, TA_ECDSA_GEN_KEY, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(Genrate Key) failed 0x%x origin 0x%x",
		     res, origin);
}

TEEC_Result sign_verify_digest(struct ecdsa_ctx *ctx, void *sig, size_t *sig_len,
			void *digest, size_t digest_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = digest;
	op.params[0].tmpref.size = digest_len;
	op.params[1].tmpref.buffer = sig;
	op.params[1].tmpref.size = *sig_len;

	res = TEEC_InvokeCommand(&ctx->sess, TA_ECDSA_SIGN_VERIFY_DIGEST,
				 &op, &origin);
	if (res == TEEC_SUCCESS) {
		*sig_len = op.params[1].tmpref.size;
	} else {
		printf("TEEC_InvokeCommand(Sign Verify) failed 0x%x origin 0x%x",
		     res, origin);
	}
	return res;
}

int main(int argc, char *argv[])
{
	struct ecdsa_ctx ctx;
	TEEC_Result res;
	char message[] = "hello world";
	size_t msg_len = strlen(message);
	uint8_t sig[512];
	size_t sig_len = sizeof(sig);
	uint8_t digest[64];
	size_t digest_len = sizeof(digest);
	char *algo;

	if (argc > 1) {
		algo = argv[1];
		printf("%s algo selected\n", algo);
		if (strcmp(algo, "ECDSA_SHA1") == 0) {
			ctx.selected_algo = TEE_ALG_ECDSA_SHA1;
		} else if (strcmp(algo, "ECDSA_SHA224") == 0) {
			ctx.selected_algo = TEE_ALG_ECDSA_SHA224;
		} else if (strcmp(algo, "ECDSA_SHA256") == 0) {
			ctx.selected_algo = TEE_ALG_ECDSA_SHA256;
		} else if (strcmp(algo, "ECDSA_SHA384") == 0) {
			ctx.selected_algo = TEE_ALG_ECDSA_SHA384;
		} else if (strcmp(algo, "ECDSA_SHA512") == 0) {
			ctx.selected_algo = TEE_ALG_ECDSA_SHA512;
		} else {
			printf("%s algo is invalid\n", algo);
			usage(argv[0]);
			exit(1);
		}
	} else {
		printf("ECDSA_SHA256 algo selected\n");
		ctx.selected_algo = TEE_ALG_ECDSA_SHA256;
	}

	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	printf("Compute digest\n");
	compute_digest(&ctx, (void *)message, msg_len, (void *)digest,
		       &digest_len);

	printf("genrate the key\n");
	genrate_key(&ctx);

	printf("Sign and Verify the digest\n");
	res = sign_verify_digest(&ctx, sig, &sig_len,
				 (void *)digest, digest_len);
	if (res != TEEC_SUCCESS) {
		printf("sign failed to verify\n");
		errx(1, "TEEC_InvokeCommand failed: 0x%x", res);
	} else {
		printf("verify signature successfully.\n");
	}

	printf("signature: ");
	for (size_t i = 0; i < sig_len; i++)
		printf("%02x ", sig[i]);
	printf("\n");

	terminate_tee_session(&ctx);
	return 0;
}
