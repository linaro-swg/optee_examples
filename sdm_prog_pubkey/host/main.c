// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include <sdm_prog_pubkey_ta.h>

#define SDM_PROG_PUBKEY_MAX_KEYS	SDM_PUBKEY_MAX_HASHES_PER_CALL

static void usage(const char *prog, int exit_code)
{
	FILE *fp = (exit_code == 0) ? stdout : stderr;

	fprintf(fp,
		"Usage: %s -i <hash_file> [-i <hash_file> ...] [--non-volatile]\n"
		"\n"
		"  -i, --input <file>   raw binary key-hash file; repeatable up to\n"
		"                       %u times.  A single -i may be %u bytes\n"
		"                       (SHA-256 / secp256r1) or %u bytes\n"
		"                       (SHA-384 / secp384r1).  Two or more -i\n"
		"                       must each be exactly %u bytes (SHA-384);\n"
		"                       they are concatenated, in order, into one\n"
		"                       batch programmed in a single SDM call.\n"
		"                       At least one -i is required.\n"
		"      --non-volatile   *** PERMANENTLY BURN THE PHYSICAL eFUSE ***\n"
		"                       Clears the SDM test bit (T=0); once\n"
		"                       written the owner-root key hash(es) CANNOT\n"
		"                       be erased or changed.  Default (omit)\n"
		"                       is test/cache-only (T=1, virtual fuse).\n"
		"  -h, --help           show this help and exit\n"
		"\n"
		"SMC flags word (x2) layout, built by the PTA:\n"
		"  bit[31]    T (test/cache-only)  1 = default, 0 = --non-volatile\n"
		"  bit[30]    S (skip cancel)      always 0\n"
		"  bits[15:8] key-set count        (number of -i inputs) - 1\n"
		"  bits[1:0]  hash_type            1 = secp256r1 (single 32-byte input)\n"
		"                                  2 = secp384r1 (1..%u batched 48-byte inputs)\n"
		"\n"
		"Examples:\n"
		"  %s -i root0.qky.hash.bin --non-volatile\n"
		"  %s -i root0.qky.hash.bin -i root1.qky.hash.bin -i root2.qky.hash.bin\n"
		"\n"
		"Exit status: 0 = accepted, 1 = rejected or error,\n"
		"             2 = --non-volatile burn done but phase-2 did not finalize\n",
		prog, SDM_PROG_PUBKEY_MAX_KEYS, SDM_PUBKEY_HASH_SIZE_SHA256,
		SDM_PUBKEY_HASH_SIZE_SHA384, SDM_PUBKEY_HASH_SIZE_SHA384,
		SDM_PROG_PUBKEY_MAX_KEYS, prog, prog);
	exit(exit_code);
}

static long probe_hash_file_size(const char *path)
{
	FILE *fp = fopen(path, "rb");
	long len = 0;

	if (!fp)
		err(1, "open %s", path);

	if (fseek(fp, 0, SEEK_END) != 0)
		err(1, "fseek %s", path);
	len = ftell(fp);
	if (len < 0)
		err(1, "ftell %s", path);

	fclose(fp);
	return len;
}

static void read_hash_chunk(const char *path, uint8_t *buf, size_t expected)
{
	FILE *fp = fopen(path, "rb");
	long len = 0;
	size_t got = 0;

	if (!fp)
		err(1, "open %s", path);

	if (fseek(fp, 0, SEEK_END) != 0)
		err(1, "fseek %s", path);
	len = ftell(fp);
	if (len < 0)
		err(1, "ftell %s", path);
	if ((size_t)len != expected)
		errx(1, "%s: hash file is %ld bytes (expected exactly %zu)",
		     path, len, expected);

	rewind(fp);
	got = fread(buf, 1, expected, fp);
	if (got != expected)
		err(1, "fread %s (got %zu of %zu bytes)",
		    path, got, expected);

	fclose(fp);
}

static void print_hash(const uint8_t *buf, size_t size)
{
	size_t i = 0;

	for (i = 0; i < size; i++) {
		printf("%02x", buf[i]);
		if ((i & 0xF) == 0xF && i != size - 1)
			printf("\n  ");
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	static const struct option long_opts[] = {
		{ "input",        required_argument, NULL, 'i' },
		{ "non-volatile", no_argument,       NULL,  1  },
		{ "help",         no_argument,       NULL, 'h' },
		{ NULL,           0,                 NULL,  0  },
	};

	TEEC_Result res = 0;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_SharedMemory hash_shm = { };
	TEEC_UUID uuid = TA_SDM_PROG_PUBKEY_UUID;
	uint32_t err_origin = 0;
	const char *input_paths[SDM_PROG_PUBKEY_MAX_KEYS] = { };
	unsigned int num_inputs = 0;
	uint8_t *hash_buf = NULL;
	size_t hash_size = 0;
	uint32_t sdm_resp = 0;
	uint32_t smc_hdr = 0;
	uint32_t phase2 = 0;
	uint32_t submitted = 0;
	uint32_t host_flags = 0;
	bool non_volatile = false;
	bool is_sha256 = false;
	int opt = 0;
	unsigned int i = 0;
	int exit_code = 1;

	while ((opt = getopt_long(argc, argv, "i:h", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'i':
			if (num_inputs >= SDM_PROG_PUBKEY_MAX_KEYS) {
				fprintf(stderr,
					"%s: too many -i (max %u)\n",
					argv[0], SDM_PROG_PUBKEY_MAX_KEYS);
				usage(argv[0], 1);
			}
			input_paths[num_inputs++] = optarg;
			break;
		case 1:		/* --non-volatile */
			non_volatile = true;
			break;
		case 'h':
			usage(argv[0], 0);
			break;
		default:
			usage(argv[0], 1);
		}
	}

	if (optind != argc) {
		fprintf(stderr, "%s: unexpected argument: %s\n",
			argv[0], argv[optind]);
		usage(argv[0], 1);
	}
	if (num_inputs == 0) {
		fprintf(stderr, "%s: at least one -i <hash_file> is required\n",
			argv[0]);
		usage(argv[0], 1);
	}

	if (num_inputs == 1) {
		long len = probe_hash_file_size(input_paths[0]);

		if (len == (long)SDM_PUBKEY_HASH_SIZE_SHA256) {
			hash_size = SDM_PUBKEY_HASH_SIZE_SHA256;
			is_sha256 = true;
		} else if (len == (long)SDM_PUBKEY_HASH_SIZE_SHA384) {
			hash_size = SDM_PUBKEY_HASH_SIZE_SHA384;
		} else {
			errx(1, "%s: hash file is %ld bytes (expected %u or %u)",
			     input_paths[0], len, SDM_PUBKEY_HASH_SIZE_SHA256,
			     SDM_PUBKEY_HASH_SIZE_SHA384);
		}

		hash_buf = malloc(hash_size);
		if (!hash_buf)
			err(1, "malloc(%zu)", hash_size);

		read_hash_chunk(input_paths[0], hash_buf, hash_size);
	} else {
		hash_size = (size_t)num_inputs * SDM_PUBKEY_HASH_SIZE_SHA384;

		hash_buf = malloc(hash_size);
		if (!hash_buf)
			err(1, "malloc(%zu)", hash_size);

		for (i = 0; i < num_inputs; i++)
			read_hash_chunk(input_paths[i],
					hash_buf + (size_t)i *
						SDM_PUBKEY_HASH_SIZE_SHA384,
					SDM_PUBKEY_HASH_SIZE_SHA384);
	}

	if (non_volatile) {
		host_flags |= SDM_PUBKEY_HOST_FLAG_NON_VOLATILE;
		fprintf(stderr,
			"\n"
			"  ************************************************************\n"
			"  *  WARNING: --non-volatile selected.                       *\n"
			"  *  The SDM will PERMANENTLY burn %u owner-root key hash(es)*\n"
			"  *  into the physical eFuse (T=0).                          *\n"
			"  *  This action is IRREVERSIBLE.                            *\n"
			"  ************************************************************\n"
			"\n",
			num_inputs);
	} else {
		fprintf(stderr,
			"\n"
			"  ************************************************************\n"
			"  *                     ***** Virtual *****                  *\n"
			"  *  Default mode: SDM test bit T=1 (x2 bit[31]).            *\n"
			"  *  %u owner-root key hash(es) written to the virtual /     *\n"
			"  *  cache-only fuse.  No physical eFuse burned.             *\n"
			"  *  Re-run with --non-volatile to PERMANENTLY burn.         *\n"
			"  ************************************************************\n"
			"\n",
			num_inputs);
	}

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

	hash_shm.buffer = hash_buf;
	hash_shm.size   = hash_size;
	hash_shm.flags  = TEEC_MEM_INPUT;
	res = TEEC_RegisterSharedMemory(&ctx, &hash_shm);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_RegisterSharedMemory: 0x%x\n", res);
		goto out_sess;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_OUTPUT);
	op.params[0].memref.parent = &hash_shm;
	op.params[0].memref.size   = hash_size;
	op.params[1].value.a       = host_flags;
	op.params[1].value.b       = 0;

	res = TEEC_InvokeCommand(&sess, TA_SDM_PROG_PUBKEY_CMD_SET,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr,
			"TA_SDM_PROG_PUBKEY_CMD_SET: 0x%x (origin 0x%x)\n",
			res, err_origin);
		goto out_shm;
	}

	sdm_resp  = op.params[2].value.a;
	smc_hdr   = op.params[2].value.b;
	phase2    = op.params[3].value.a;
	submitted = op.params[3].value.b;

	printf("\nSDM owner-root key programming (%s):\n",
	       non_volatile ? "NON-VOLATILE / eFuse burn (T=0)"
			    : "***** Virtual ***** / cache-only (T=1)");
	printf("  hash type     : %s\n",
	       is_sha256 ? "SHA-256 / secp256r1" : "SHA-384 / secp384r1");
	printf("  keys in batch : %u\n", num_inputs);
	for (i = 0; i < num_inputs; i++) {
		size_t unit = is_sha256 ? SDM_PUBKEY_HASH_SIZE_SHA256
					: SDM_PUBKEY_HASH_SIZE_SHA384;

		printf("  [%u] %s (%zu bytes):\n  ", i, input_paths[i], unit);
		print_hash(hash_buf + i * unit, unit);
	}
	printf("  SDM response  : 0x%08" PRIx32 "\n", sdm_resp);
	printf("  SMC resp hdr  : 0x%08" PRIx32 "\n", smc_hdr);
	printf("  phase2 status : 0x%08" PRIx32 "\n", phase2);
	printf("  keys submitted: %" PRIu32 "\n", submitted);

	if (sdm_resp == 0) {
		bool phase2_ok = (phase2 == SDM_PHASE2_STATUS_SUCCESS) ||
				 (phase2 == SDM_PHASE2_STATUS_NOP);

		if (non_volatile && !phase2_ok) {
			printf("  Result        : INCOMPLETE"
			       " (eFuse burned, phase-2 did NOT finalize)\n\n");
			fprintf(stderr,
				"  ************************************************************\n"
				"  *  WARNING: the %u owner-root key hash(es) WERE burned     *\n"
				"  *  into the physical eFuse, but phase-2 finalize failed    *\n"
				"  *  (phase2 status 0x%08" PRIx32 ").  No Soft POR was triggered,  *\n"
				"  *  so the device is NOT finalized.  Verify the SDM         *\n"
				"  *  firmware implements EFUSE_PUBKEY_PROGRAM_PHASE2         *\n"
				"  *  (mailbox cmd 0x79) before relying on this device.       *\n"
				"  ************************************************************\n\n",
				num_inputs, phase2);
			exit_code = 2;
		} else {
			printf("  Result        : ACCEPTED%s\n\n",
			       non_volatile ? " (eFuse permanently burned)"
					    : " (virtual / cache-only)");
			exit_code = 0;
		}
	} else {
		fprintf(stderr,
			"  Result        : REJECTED "
			"(sdm_resp=0x%08" PRIx32 " smc_hdr=0x%08" PRIx32 ")\n\n",
			sdm_resp, smc_hdr);
		exit_code = 1;
	}

out_shm:
	TEEC_ReleaseSharedMemory(&hash_shm);
out_sess:
	TEEC_CloseSession(&sess);
out_ctx:
	TEEC_FinalizeContext(&ctx);
	free(hash_buf);
	return exit_code;
}
