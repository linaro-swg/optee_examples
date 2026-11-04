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

#include <sdm_send_cert_ta.h>

static const char *cert_type_name(uint32_t cert_type)
{
	switch (cert_type) {
	case SDM_CERT_TYPE_ENGINEERING:		return "ENGINEERING (0x01)";
	case SDM_CERT_TYPE_USER_AES_ROOT_KEY:	return "USER_AES_ROOT_KEY (0x02)";
	case SDM_CERT_TYPE_RMA:			return "RMA (0x03)";
	case SDM_CERT_TYPE_DEBUG:		return "DEBUG (0x04)";
	case SDM_CERT_TYPE_COUNTER_SET:		return "COUNTER_SET (0x05)";
	case SDM_CERT_TYPE_VAB_SRC:		return "VAB_SRC (0x06)";
	case SDM_CERT_TYPE_PR_OWNER_PUBKEY:	return "PR_OWNER_PUBKEY (0x07)";
	case SDM_CERT_TYPE_KILL_PERMIT:		return "KILL_PERMIT (0x08)";
	case SDM_CERT_TYPE_OWNER_PUBKEY_LATE:	return "OWNER_PUBKEY_LATE (0x09)";
	case SDM_CERT_TYPE_DECOMMISSION:	return "DECOMMISSION (0x0A)";
	case SDM_CERT_TYPE_CANCEL_SDOS_SRK:	return "CANCEL_SDOS_SRK (0x0B)";
	case SDM_CERT_TYPE_PROVISION_SDOS_SRK:	return "PROVISION_SDOS_SRK (0x0C)";
	case SDM_CERT_TYPE_CANCEL_USER_AES:	return "CANCEL_USER_AES (0x0D)";
	case SDM_CERT_TYPE_OWNERSHIP_XFER_FROM:	return "OWNERSHIP_XFER_FROM (0x0E)";
	case SDM_CERT_TYPE_OWNERSHIP_XFER_TO:	return "OWNERSHIP_XFER_TO (0x0F)";
	case SDM_CERT_TYPE_BETA_PREVIEW:	return "BETA_PREVIEW";
	case SDM_CERT_TYPE_BETA_LOCAL:		return "BETA_LOCAL";
	default:				return "UNKNOWN";
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <cert_file>\n"
		"\n"
		"  cert_file  SDM certificate binary (max %u bytes,\n"
		"             4-byte aligned size, well-formed header)\n"
		"\n"
		"Supported cert_type values (offset 0x0C):\n"
		"  0x01 ENGINEERING        0x02 USER_AES_ROOT_KEY\n"
		"  0x03 RMA                0x04 DEBUG\n"
		"  0x05 COUNTER_SET        0x06 VAB_SRC\n"
		"  0x07 PR_OWNER_PUBKEY    0x08 KILL_PERMIT\n"
		"  0x09 OWNER_PUBKEY_LATE  0x0A DECOMMISSION\n"
		"  0x0B CANCEL_SDOS_SRK    0x0C PROVISION_SDOS_SRK\n"
		"  0x0D CANCEL_USER_AES    0x0E OWNERSHIP_XFER_FROM\n"
		"  0x0F OWNERSHIP_XFER_TO\n"
		"  0x42444350 BETA_PREVIEW 0x4244434C BETA_LOCAL\n"
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
	if ((size_t)len < VAB_CERT_MIN_SIZE)
		errx(1, "certificate size %ld < minimum (%u bytes)",
		     len, (unsigned)VAB_CERT_MIN_SIZE);

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

static void log_cert_header(const uint8_t *buf, size_t len)
{
	const struct sdm_cert_hdr *hdr = (const struct sdm_cert_hdr *)buf;

	if (len < sizeof(*hdr))
		return;

	printf("sdm_send_cert: cert_magic=0x%08" PRIx32
	       " cert_data_sz=%u cert_ver=%u cert_type=%s\n",
	       hdr->cert_magic_num, hdr->cert_data_sz, hdr->cert_ver,
	       cert_type_name(hdr->cert_type));
}

int main(int argc, char *argv[])
{
	TEEC_Result res = 0;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_SharedMemory cert_shm = { };
	TEEC_UUID uuid = TA_SDM_SEND_CERT_UUID;
	uint32_t err_origin = 0;
	uint8_t *cert_buf = NULL;
	size_t cert_size = 0;
	uint32_t mbox_err = 0;
	uint32_t resp_detail = 0;
	int exit_code = 1;

	if (argc != 2)
		usage(argv[0]);

	cert_buf = read_cert(argv[1], &cert_size);
	log_cert_header(cert_buf, cert_size);

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

	res = TEEC_InvokeCommand(&sess, TA_SDM_SEND_CERT_CMD_SEND,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr,
			"TA_SDM_SEND_CERT_CMD_SEND: 0x%x (origin 0x%x)\n",
			res, err_origin);
		goto out_shm;
	}

	mbox_err    = op.params[1].value.a;
	resp_detail = op.params[1].value.b;

	if (mbox_err == 0) {
		printf("Certificate submission: PASS\n");
		exit_code = 0;
	} else {
		fprintf(stderr,
			"Certificate submission: FAIL "
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
