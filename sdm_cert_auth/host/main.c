// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include <sdm_cert_auth_ta.h>

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <cert_file>\n"
		"\n"
		"  cert_file  VAB certificate binary (max %u bytes,\n"
		"             4-byte aligned size, valid VAB header)\n"
		"\n"
		"Exit status: 0 = accepted, 1 = rejected or error\n",
		prog, SDM_CERT_MAX_SIZE);
	exit(1);
}

static uint8_t *read_cert(const char *path, size_t *out_len)
{
	FILE *fp = fopen(path, "rb");
	long len = 0;
	uint8_t *buf = NULL;

	if (!fp)
		err(1, "open %s", path);

	if (fseek(fp, 0, SEEK_END) != 0)
		err(1, "fseek");
	len = ftell(fp);
	if (len <= 0)
		errx(1, "certificate file is empty or unreadable");
	if ((size_t)len > SDM_CERT_MAX_SIZE)
		errx(1, "certificate too large: %ld bytes (max %u)",
		     len, SDM_CERT_MAX_SIZE);
	if ((size_t)len & 0x3U)
		errx(1, "certificate size %ld is not 4-byte aligned", len);
	if ((size_t)len < VAB_CERT_HEADER_SIZE)
		errx(1, "certificate size %ld < VAB header (%u bytes)",
		     len, (unsigned)VAB_CERT_HEADER_SIZE);

	rewind(fp);
	buf = malloc((size_t)len);
	if (!buf)
		err(1, "malloc");

	if (fread(buf, 1, (size_t)len, fp) != (size_t)len)
		err(1, "fread");

	fclose(fp);
	*out_len = (size_t)len;
	return buf;
}

int main(int argc, char *argv[])
{
	TEEC_Result res = 0;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_SharedMemory cert_shm = { };
	TEEC_UUID uuid = TA_SDM_CERT_AUTH_UUID;
	uint32_t err_origin = 0;
	uint8_t *cert_buf = NULL;
	size_t cert_size = 0;
	uint32_t mbox_err = 0;
	uint32_t resp_detail = 0;
	int exit_code = 1;

	if (argc != 2)
		usage(argv[0]);

	cert_buf = read_cert(argv[1], &cert_size);

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

	cert_shm.buffer = cert_buf;
	cert_shm.size   = cert_size;
	cert_shm.flags  = TEEC_MEM_INPUT;
	res = TEEC_RegisterSharedMemory(&ctx, &cert_shm);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_RegisterSharedMemory: 0x%x\n", res);
		goto out_sess;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
					 TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = &cert_shm;
	op.params[0].memref.size   = cert_size;

	res = TEEC_InvokeCommand(&sess, TA_SDM_CERT_AUTH_CMD_SEND,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr,
			"TA_SDM_CERT_AUTH_CMD_SEND: 0x%x (origin 0x%x)\n",
			res, err_origin);
		goto out_shm;
	}

	mbox_err    = op.params[1].value.a;
	resp_detail = op.params[1].value.b;

	if (mbox_err == 0) {
		printf("Certificate authentication: PASS\n");
		exit_code = 0;
	} else {
		fprintf(stderr,
			"Certificate authentication: FAIL "
			"(mbox_err=0x%08x detail=0x%08x)\n",
			mbox_err, resp_detail);
		exit_code = 1;
	}

out_shm:
	TEEC_ReleaseSharedMemory(&cert_shm);
out_sess:
	TEEC_CloseSession(&sess);
out_ctx:
	TEEC_FinalizeContext(&ctx);
	free(cert_buf);
	return exit_code;
}
