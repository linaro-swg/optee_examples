// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>

#include <tee_client_api.h>
#include <sign_verify_ta.h>

static void usage(int argc, char *argv[])
{
	printf("%s: optee_example_sign_verify <key_size> <algo_name>\n",
	       __func__);
	printf("<key_size>:  key size in bits. Supported values are: ");
	printf("2048 bits (default), 3072 bits and 4096 bits\n");

	printf("<algo_name>: algorithm name. Supported values are:\n");
	printf("TA_ALG_PKCS1_V1_5_SHA1\n");
	printf("TA_ALG_PKCS1_V1_5_SHA224\n");
	printf("TA_ALG_PKCS1_V1_5_SHA256 (default)\n");
	printf("TA_ALG_PKCS1_V1_5_SHA384\n");
	printf("TA_ALG_PKCS1_V1_5_SHA512\n");
	printf("TA_ALG_PKCS1_PSS_MGF1_SHA1\n");
	printf("TA_ALG_PKCS1_PSS_MGF1_SHA224\n");
	printf("TA_ALG_PKCS1_PSS_MGF1_SHA256\n");
	printf("TA_ALG_PKCS1_PSS_MGF1_SHA384\n");
	printf("TA_ALG_PKCS1_PSS_MGF1_SHA512\n");

	exit(1);
}

static void get_args(int argc, char *argv[], size_t *key_size,
		     uint32_t *selected_alg)
{
	char *ep;
	long ks = 2048;
	char *algo;

	if (argc > 3)
		usage(argc, argv);

	if (argc > 1) {
		ks = strtol(argv[1], &ep, 0);
		if (*ep) {
			warnx("cannot parse key_size \"%s\"", argv[1]);
			usage(argc, argv);
		}
	}

	if (ks < 0 || ks == LONG_MAX) {
		warnx("bad key_size \"%s\" (%ld)", argv[1], ks);
		usage(argc, argv);
	}

	*key_size = ks;
	printf("Key size: %zu\n", *key_size);

	if (argc > 2) {
		algo = argv[2];
		printf("%s algo selected\n", algo);
		if (strcmp(algo, "TA_ALG_PKCS1_V1_5_SHA1") == 0) {
			*selected_alg = TA_ALG_PKCS1_V1_5_SHA1;
		} else if (strcmp(algo, "TA_ALG_PKCS1_V1_5_SHA224") == 0) {
			*selected_alg = TA_ALG_PKCS1_V1_5_SHA224;
		} else if (strcmp(algo, "TA_ALG_PKCS1_V1_5_SHA256") == 0) {
			*selected_alg = TA_ALG_PKCS1_V1_5_SHA256;
		} else if (strcmp(algo, "TA_ALG_PKCS1_V1_5_SHA384") == 0) {
			*selected_alg = TA_ALG_PKCS1_V1_5_SHA384;
		} else if (strcmp(algo, "TA_ALG_PKCS1_V1_5_SHA512") == 0) {
			*selected_alg = TA_ALG_PKCS1_V1_5_SHA512;
		} else if (strcmp(algo, "TA_ALG_PKCS1_PSS_MGF1_SHA1") == 0) {
			*selected_alg = TA_ALG_PKCS1_PSS_MGF1_SHA1;
		} else if (strcmp(algo, "TA_ALG_PKCS1_PSS_MGF1_SHA224") == 0) {
			*selected_alg = TA_ALG_PKCS1_PSS_MGF1_SHA224;
		} else if (strcmp(algo, "TA_ALG_PKCS1_PSS_MGF1_SHA256") == 0) {
			*selected_alg = TA_ALG_PKCS1_PSS_MGF1_SHA256;
		} else if (strcmp(algo, "TA_ALG_PKCS1_PSS_MGF1_SHA384") == 0) {
			*selected_alg = TA_ALG_PKCS1_PSS_MGF1_SHA384;
		} else if (strcmp(algo, "TA_ALG_PKCS1_PSS_MGF1_SHA512") == 0) {
			*selected_alg = TA_ALG_PKCS1_PSS_MGF1_SHA512;
		} else {
			printf("%s algo is invalid\n", algo);
			usage(argc, argv);
		}
	} else {
		printf("TA_ALG_PKCS1_V1_5_SHA256 algo selected\n");
		*selected_alg = TA_ALG_PKCS1_V1_5_SHA256;
	}

}

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SIGN_VERIFY_UUID;
	uint32_t origin;
	char message[] = "HelloFromHost";
	uint8_t signature[MAX_SIG_SIZE];
	size_t sig_len = sizeof(signature);
	uint32_t selected_alg;
	size_t key_size;

	get_args(argc, argv, &key_size, &selected_alg);

	printf("Prepare session with the TA\n");
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed: 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed: 0x%x origin: 0x%x", res,
		     origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT);
	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = strlen(message);
	op.params[1].tmpref.buffer = signature;
	op.params[1].tmpref.size = (uint32_t)sig_len;
	op.params[2].value.a = selected_alg;
	op.params[3].value.a = key_size;

	printf("Prepare sign and verify operations\n");
	res = TEEC_InvokeCommand(&sess, TA_RSA_SIGN_CMD_SIGN_VERIFY, &op,
				 &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed: 0x%x origin: 0x%x", res,
		     origin);
	printf("Sign and verify successful. Signature length: %zu bytes\n",
	       op.params[1].tmpref.size);

	printf("Signature: ");
	for (size_t i = 0; i < op.params[1].tmpref.size; i++)
		printf("%02x ", signature[i]);

	printf("\n");

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
