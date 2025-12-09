// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <err.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <acipher_ta.h>

#define ENCRYPT         1
#define DECRYPT         0

static void usage(int argc, char *argv[])
{
	const char *pname = argv[0];

	fprintf(stderr, "Usage: %s <key_size> <string to encrypt> [<algo name>]\n\n",
		pname);
	fprintf(stderr, "<key_size>:  key size in bits. Supported values are:\n");
	fprintf(stderr, "             2048, 3072, 4096\n");
	fprintf(stderr, "<algo_name>: algorithm name. Supported values are:\n");
	fprintf(stderr, "             TA_ALG_PKCS1_V1_5 (default)\n");
	fprintf(stderr, "             TA_ALG_OAEP_MGF1_SHA1\n");
	fprintf(stderr, "             TA_ALG_OAEP_MGF1_SHA224\n");
	fprintf(stderr, "             TA_ALG_OAEP_MGF1_SHA256\n");
	fprintf(stderr, "             TA_ALG_OAEP_MGF1_SHA384\n");
	fprintf(stderr, "             TA_ALG_OAEP_MGF1_SHA512\n");
	exit(1);
}

static void get_args(int argc, char *argv[], size_t *key_size, void **inbuf,
		     size_t *inbuf_len, uint32_t *algo_num)
{
	char *ep;
	long ks;
	char *algo;

	if (argc < 3 || argc > 4) {
		warnx("Unexpected number of arguments %d", argc - 1);
		usage(argc, argv);
	}

	ks = strtol(argv[1], &ep, 0);
	if (*ep) {
		warnx("cannot parse key_size \"%s\"", argv[1]);
		usage(argc, argv);
	}
	if (ks < 0 || ks == LONG_MAX) {
		warnx("bad key_size \"%s\" (%ld)", argv[1], ks);
		usage(argc, argv);
	}
	*key_size = ks;

	*inbuf = argv[2];
	*inbuf_len = strlen(argv[2]);

	if (argc > 3) {
		algo = argv[3];
		printf("%s algo selected\n", algo);
		if (strcmp(algo, "TA_ALG_OAEP_MGF1_SHA1") == 0) {
			*algo_num = TA_ALG_OAEP_MGF1_SHA1;
		} else if (strcmp(algo, "TA_ALG_OAEP_MGF1_SHA224") == 0) {
			*algo_num = TA_ALG_OAEP_MGF1_SHA224;
		} else if (strcmp(algo, "TA_ALG_OAEP_MGF1_SHA256") == 0) {
			*algo_num = TA_ALG_OAEP_MGF1_SHA256;
		} else if (strcmp(algo, "TA_ALG_OAEP_MGF1_SHA384") == 0) {
			*algo_num = TA_ALG_OAEP_MGF1_SHA384;
		} else if (strcmp(algo, "TA_ALG_OAEP_MGF1_SHA512") == 0) {
			*algo_num = TA_ALG_OAEP_MGF1_SHA512;
		} else if (strcmp(algo, "TA_ALG_PKCS1_V1_5") == 0) {
			*algo_num = TA_ALG_PKCS1_V1_5;
		} else {
			fprintf(stderr, "%s algo is invalid\n", algo);
			usage(argc, argv);
		}
	} else {
		printf("TA_ALG_PKCS1_V1_5 algo selected\n");
		*algo_num = TA_ALG_PKCS1_V1_5;
	}


}

static void teec_err(TEEC_Result res, uint32_t eo, const char *str)
{
	errx(1, "%s: %#" PRIx32 " (error origin %#" PRIx32 ")", str, res, eo);
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
	uint32_t eo;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	size_t key_size;
	void *inbuf;
	size_t inbuf_len;
	void *outbuf = NULL;
	size_t outbuf_len = 0;
	size_t n;
	uint32_t algo_num;
	const TEEC_UUID uuid = TA_ACIPHER_UUID;

	get_args(argc, argv, &key_size, &inbuf, &inbuf_len, &algo_num);

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		errx(1, "TEEC_InitializeContext(NULL, x): %#" PRIx32, res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &eo);
	if (res)
		teec_err(res, eo, "TEEC_OpenSession(TEEC_LOGIN_PUBLIC)");

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = key_size;

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_GEN_KEY, &op, &eo);
	if (res)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_GEN_KEY)");

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_VALUE_INPUT);
	op.params[0].tmpref.buffer = inbuf;
	op.params[0].tmpref.size = inbuf_len;
	op.params[2].value.a = ENCRYPT; /* encrypt */
	op.params[3].value.a = algo_num;

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT_DECRYPT, &op, &eo);
	if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER)
		teec_err(res, eo, "Command TA_ACIPHER_CMD_ENCRYPT_DECRYPT failed for encryption");

	outbuf_len = op.params[1].tmpref.size;
	op.params[1].tmpref.buffer = malloc(op.params[1].tmpref.size);
	if (!op.params[1].tmpref.buffer)
		err(1, "Cannot allocate out buffer of size %zu",
		    outbuf_len);

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT_DECRYPT, &op, &eo);
	if (res)
		teec_err(res, eo, "Command TA_ACIPHER_CMD_ENCRYPT_DECRYPT failed for encryption");

	outbuf = malloc(outbuf_len);
	if (!outbuf)
		err(1, "Cannot allocate out buffer of size %zu", outbuf_len);

	memmove(outbuf, op.params[1].tmpref.buffer, outbuf_len);
	printf("Encrypted buffer: ");
	for (n = 0; n < outbuf_len; n++)
		printf("%02x ", ((uint8_t *)outbuf)[n]);
	printf("\n");

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_VALUE_INPUT);
	op.params[0].tmpref.buffer = outbuf;
	op.params[0].tmpref.size = outbuf_len;
	op.params[2].value.a = DECRYPT; /* decrypt */
	op.params[3].value.a = algo_num;

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT_DECRYPT, &op, &eo);
	if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER)
		teec_err(res, eo, "Command TA_ACIPHER_CMD_ENCRYPT_DECRYPT failed for decryption");

	op.params[1].tmpref.buffer = malloc(op.params[1].tmpref.size);
	if (!op.params[1].tmpref.buffer)
		err(1, "Cannot allocate out buffer of size %zu",
		    outbuf_len);

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT_DECRYPT, &op, &eo);
	if (res)
		teec_err(res, eo, "Command TA_ACIPHER_CMD_ENCRYPT_DECRYPT failed for decryption");

	if (memcmp(inbuf, op.params[1].tmpref.buffer, op.params[1].tmpref.size))
		printf("message is not matching\n");
	else
		printf("message is matching successfully\n");

	return 0;
}
