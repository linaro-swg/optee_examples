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

/* To the the UUID (found the the TA's h-file(s)) */
#include <acipher_ta.h>

static void usage(int argc, char *argv[])
{
	const char *pname = "acipher";

	if (argc)
		pname = argv[0];

	fprintf(stderr, "usage: %s <key_size> <string to encrypt>\n", pname);
	exit(1);
}

static void get_args(int argc, char *argv[], size_t *key_size, void **inbuf,
		     size_t *inbuf_len)
{
	char *ep;
	long ks;

	if (argc != 3) {
		warnx("Unexpected number of arguments %d (expected 2)",
		      argc - 1);
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
	size_t n;
	const TEEC_UUID uuid = TA_ACIPHER_UUID;

	get_args(argc, argv, &key_size, &inbuf, &inbuf_len);

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
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = inbuf;
	op.params[0].tmpref.size = inbuf_len;

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT, &op, &eo);
	if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_ENCRYPT)");

	op.params[1].tmpref.buffer = malloc(op.params[1].tmpref.size);
	if (!op.params[1].tmpref.buffer)
		err(1, "Cannot allocate out buffer of size %zu",
		    op.params[1].tmpref.size);

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT, &op, &eo);
	if (res)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_ENCRYPT)");

	printf("Encrypted buffer: ");
	for (n = 0; n < op.params[1].tmpref.size; n++)
		printf("%02x ", ((uint8_t *)op.params[1].tmpref.buffer)[n]);
	printf("\n");
	return 0;
}
