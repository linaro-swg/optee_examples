// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024-2026, Intel Corporation
 */

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include <sdm_crypt_ta.h>

/* -------------------------------------------------------------------------
 * File helpers
 * ---------------------------------------------------------------------- */

static uint8_t *read_file(const char *path, size_t *out_len)
{
	FILE *fp = fopen(path, "rb");
	uint8_t *buf = NULL;
	long len = 0;

	if (!fp)
		err(1, "open %s", path);

	if (fseek(fp, 0, SEEK_END) != 0)
		err(1, "fseek %s", path);
	len = ftell(fp);
	if (len < 0)
		err(1, "ftell %s", path);
	rewind(fp);

	buf = malloc((size_t)len);
	if (!buf)
		err(1, "malloc");

	if (fread(buf, 1, (size_t)len, fp) != (size_t)len)
		err(1, "fread %s", path);

	fclose(fp);
	*out_len = (size_t)len;
	return buf;
}

static void write_file(const char *path, const uint8_t *buf, size_t len)
{
	FILE *fp = fopen(path, "wb");

	if (!fp)
		err(1, "open %s for write", path);
	if (fwrite(buf, 1, len, fp) != len)
		err(1, "fwrite %s", path);
	fclose(fp);
}

/* -------------------------------------------------------------------------
 * TA session
 * ---------------------------------------------------------------------- */

static void open_ta_session(TEEC_Context *ctx, TEEC_Session *sess)
{
	TEEC_UUID uuid = TA_SDM_CRYPT_UUID;
	uint32_t err_origin = 0;
	TEEC_Result res;

	res = TEEC_InitializeContext(NULL, ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext: 0x%x", res);

	res = TEEC_OpenSession(ctx, sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession: 0x%x (origin 0x%x)",
		     res, err_origin);
}

/* -------------------------------------------------------------------------
 * Encrypt
 * ---------------------------------------------------------------------- */

static void do_encrypt(TEEC_Context *ctx, TEEC_Session *sess,
		       uint64_t owner_id, uint32_t srk_index,
		       const char *in_path, const char *out_path)
{
	size_t plaintext_len = 0;
	uint8_t *plaintext = read_file(in_path, &plaintext_len);
	size_t pad_len = SDOS_PAD_LEN(plaintext_len);
	size_t src_size = (size_t)SDOS_HDR_SIZE + plaintext_len + pad_len;
	size_t dst_size = src_size + (size_t)SDOS_HMAC_SIZE;
	uint8_t *src_buf = calloc(1, src_size);
	uint8_t *dst_buf = NULL;
	struct sdos_hdr *hdr = NULL;
	TEEC_SharedMemory src_shm = { };
	TEEC_SharedMemory dst_shm = { };
	TEEC_Operation op = { };
	uint32_t err_origin = 0;
	TEEC_Result res;
	size_t out_len = 0;

	if (!src_buf)
		err(1, "calloc src_buf");

	hdr = (struct sdos_hdr *)src_buf;
	hdr->magic       = SDOS_ENCRYPT_IN_MAGIC;
	hdr->data_len    = (uint32_t)(plaintext_len + pad_len);
	hdr->flags       = SDOS_FLAGS(1, srk_index, (uint32_t)pad_len);
	hdr->owner_id[0] = (uint32_t)(owner_id & 0xFFFFFFFFU);
	hdr->owner_id[1] = (uint32_t)(owner_id >> 32);
	hdr->hdr_pad     = SDOS_HDR_PAD_MAGIC;
	/* iv is zero from calloc */

	memcpy(src_buf + SDOS_HDR_SIZE, plaintext, plaintext_len);
	free(plaintext);

	dst_buf = malloc(dst_size);
	if (!dst_buf)
		err(1, "malloc dst_buf");

	src_shm.buffer = src_buf;
	src_shm.size   = src_size;
	src_shm.flags  = TEEC_MEM_INPUT;
	dst_shm.buffer = dst_buf;
	dst_shm.size   = dst_size;
	dst_shm.flags  = TEEC_MEM_OUTPUT;

	res = TEEC_RegisterSharedMemory(ctx, &src_shm);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory src: 0x%x", res);
	res = TEEC_RegisterSharedMemory(ctx, &dst_shm);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory dst: 0x%x", res);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_WHOLE,
					 TEEC_MEMREF_WHOLE,
					 TEEC_NONE);
	op.params[0].value.a = TA_SDM_CRYPT_DIR_ENCRYPT;
	op.params[1].memref.parent = &src_shm;
	op.params[1].memref.size   = src_size;
	op.params[2].memref.parent = &dst_shm;
	op.params[2].memref.size   = dst_size;

	res = TEEC_InvokeCommand(sess, TA_SDM_CRYPT_CMD_RUN, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TA_SDM_CRYPT_CMD_RUN encrypt: 0x%x (origin 0x%x)",
		     res, err_origin);

	out_len = op.params[2].memref.size;
	printf("Encrypted %zu bytes -> %zu bytes SDOS blob\n",
	       plaintext_len, out_len);
	write_file(out_path, dst_buf, out_len);

	TEEC_ReleaseSharedMemory(&src_shm);
	TEEC_ReleaseSharedMemory(&dst_shm);
	free(src_buf);
	free(dst_buf);
}

/* -------------------------------------------------------------------------
 * Decrypt
 * ---------------------------------------------------------------------- */

static void do_decrypt(TEEC_Context *ctx, TEEC_Session *sess,
		       const char *in_path, const char *out_path)
{
	size_t src_size = 0;
	uint8_t *src_buf = read_file(in_path, &src_size);
	uint8_t *dst_buf = NULL;
	TEEC_SharedMemory src_shm = { };
	TEEC_SharedMemory dst_shm = { };
	TEEC_Operation op = { };
	uint32_t err_origin = 0;
	TEEC_Result res;
	size_t out_len = 0;
	const struct sdos_hdr *hdr = NULL;
	size_t plaintext_len = 0;
	uint32_t pad_len = 0;

	if (src_size < (size_t)SDOS_HDR_SIZE + (size_t)SDOS_HMAC_SIZE)
		errx(1, "input too small to be a valid SDOS blob (%zu bytes)",
		     src_size);

	dst_buf = malloc(src_size);
	if (!dst_buf)
		err(1, "malloc dst_buf");

	src_shm.buffer = src_buf;
	src_shm.size   = src_size;
	src_shm.flags  = TEEC_MEM_INPUT;
	dst_shm.buffer = dst_buf;
	dst_shm.size   = src_size;
	dst_shm.flags  = TEEC_MEM_OUTPUT;

	res = TEEC_RegisterSharedMemory(ctx, &src_shm);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory src: 0x%x", res);
	res = TEEC_RegisterSharedMemory(ctx, &dst_shm);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_RegisterSharedMemory dst: 0x%x", res);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_WHOLE,
					 TEEC_MEMREF_WHOLE,
					 TEEC_NONE);
	op.params[0].value.a = TA_SDM_CRYPT_DIR_DECRYPT;
	op.params[1].memref.parent = &src_shm;
	op.params[1].memref.size   = src_size;
	op.params[2].memref.parent = &dst_shm;
	op.params[2].memref.size   = src_size;

	res = TEEC_InvokeCommand(sess, TA_SDM_CRYPT_CMD_RUN, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TA_SDM_CRYPT_CMD_RUN decrypt: 0x%x (origin 0x%x)",
		     res, err_origin);

	out_len = op.params[2].memref.size;
	if (out_len < (size_t)SDOS_HDR_SIZE)
		errx(1, "decrypt output too small (%zu bytes)", out_len);

	hdr = (const struct sdos_hdr *)dst_buf;
	pad_len = SDOS_FLAGS_PAD_LEN(hdr->flags);
	plaintext_len = out_len - (size_t)SDOS_HDR_SIZE;
	if (pad_len <= plaintext_len)
		plaintext_len -= pad_len;

	printf("Decrypted %zu bytes SDOS blob -> %zu bytes plaintext\n",
	       src_size, plaintext_len);
	write_file(out_path, dst_buf + SDOS_HDR_SIZE, plaintext_len);

	TEEC_ReleaseSharedMemory(&src_shm);
	TEEC_ReleaseSharedMemory(&dst_shm);
	free(src_buf);
	free(dst_buf);
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage:\n"
		"  %s encrypt <owner_id_hex> <srk_index> <input.bin> <output.bin>\n"
		"  %s decrypt <input.bin> <output.bin>\n"
		"\n"
		"  owner_id_hex  16-hex-char owner ID (e.g. 0807060504030201)\n"
		"  srk_index     integer SRK index (typically 0)\n",
		prog, prog);
	exit(1);
}

int main(int argc, char *argv[])
{
	TEEC_Context ctx = { };
	TEEC_Session sess = { };

	if (argc < 2)
		usage(argv[0]);

	open_ta_session(&ctx, &sess);

	if (strcmp(argv[1], "encrypt") == 0) {
		uint64_t owner_id;
		uint32_t srk_index;

		if (argc != 6)
			usage(argv[0]);
		owner_id  = strtoull(argv[2], NULL, 16);
		srk_index = (uint32_t)strtoul(argv[3], NULL, 0);
		do_encrypt(&ctx, &sess, owner_id, srk_index, argv[4], argv[5]);
	} else if (strcmp(argv[1], "decrypt") == 0) {
		if (argc != 4)
			usage(argv[0]);
		do_decrypt(&ctx, &sess, argv[2], argv[3]);
	} else {
		usage(argv[0]);
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
