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

#include <sdm_fuse_prog_ta.h>

static void usage(const char *prog, int exit_code)
{
	FILE *fp = (exit_code == 0) ? stdout : stderr;

	fprintf(fp,
		"Usage: %s [--non-volatile] <w0> <w1> ... <w15>\n"
		"\n"
		"Program all %u SDM user-defined eFuse words.\n"
		"All %u hex word values must be supplied (with or without 0x prefix).\n"
		"\n"
		"Mode selection:\n"
		"      --non-volatile  *** PERMANENTLY BURN THE PHYSICAL eFUSE ***\n"
		"                      Clears the SDM test bit so the 16 supplied\n"
		"                      words are written into the physical eFuse.\n"
		"                      The affected user-fuse bits CANNOT be erased\n"
		"                      or changed.  IRREVERSIBLE.\n"
		"                      Default (omit this flag) is virtual /\n"
		"                      cache-only fusing — reversible across a\n"
		"                      cold reset / power cycle.\n"
		"  -h, --help          show this help and exit\n"
		"\n"
		"Exit status: 0 = programmed, 1 = error\n",
		prog, SDM_USER_FUSE_COUNT, SDM_USER_FUSE_COUNT);
	exit(exit_code);
}

int main(int argc, char *argv[])
{
	static const struct option long_opts[] = {
		{ "non-volatile", no_argument, NULL,  1  },
		{ "help",         no_argument, NULL, 'h' },
		{ NULL,           0,           NULL,  0  },
	};

	TEEC_Result res = 0;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_SharedMemory in_shm = { };
	TEEC_UUID uuid = TA_SDM_FUSE_PROG_UUID;
	uint32_t err_origin = 0;
	uint32_t fuse_data[SDM_USER_FUSE_COUNT] = { };
	uint32_t host_flags = 0;
	bool non_volatile = false;
	unsigned int i = 0;
	int c = 0;
	int positional = 0;
	int exit_code = 1;

	while ((c = getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
		switch (c) {
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

	positional = argc - optind;
	if (positional != (int)SDM_USER_FUSE_COUNT) {
		fprintf(stderr,
			"%s: expected %u hex word arguments, got %d\n",
			argv[0], SDM_USER_FUSE_COUNT, positional);
		usage(argv[0], 1);
	}

	for (i = 0; i < SDM_USER_FUSE_COUNT; i++) {
		char *endptr = NULL;
		unsigned long v = strtoul(argv[optind + (int)i], &endptr, 16);

		if (*endptr != '\0' || v > UINT32_MAX) {
			errx(1, "invalid word %u: '%s'",
			     i, argv[optind + (int)i]);
		}
		fuse_data[i] = (uint32_t)v;
	}

	if (non_volatile) {
		host_flags |= SDM_FUSE_PROG_HOST_FLAG_NON_VOLATILE;
		fprintf(stderr,
			"\n"
			"  ****************************************************************\n"
			"  *                       *** WARNING ***                        *\n"
			"  *                                                              *\n"
			"  *  --non-volatile selected.                                    *\n"
			"  *                                                              *\n"
			"  *  The SDM will permanently burn the 16 supplied hex words     *\n"
			"  *  into the physical user-eFuse on this call.                  *\n"
			"  *                                                              *\n"
			"  *  Once written, the affected user-fuse bits CANNOT be         *\n"
			"  *  erased or changed.                                          *\n"
			"  *                                                              *\n"
			"  *  This action is IRREVERSIBLE.                                *\n"
			"  ****************************************************************\n"
			"\n");
	} else {
		printf("\n"
			"  ****************************************************************\n"
			"  *                      ***** Virtual *****                     *\n"
			"  *                                                              *\n"
			"  *  Mode: virtual / cache-only (default).                       *\n"
			"  *                                                              *\n"
			"  *  The SDM will update only its cached user-fuse state with    *\n"
			"  *  the 16 supplied hex words.  No physical eFuse bit will be   *\n"
			"  *  burned by this call.                                        *\n"
			"  *                                                              *\n"
			"  *  The effect is lost on the next cold reset / power cycle.    *\n"
			"  *                                                              *\n"
			"  ****************************************************************\n"
			"\n");
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

	in_shm.buffer = fuse_data;
	in_shm.size   = SDM_USER_FUSE_SIZE;
	in_shm.flags  = TEEC_MEM_INPUT;
	res = TEEC_RegisterSharedMemory(&ctx, &in_shm);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_RegisterSharedMemory: 0x%x\n", res);
		goto out_sess;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = &in_shm;
	op.params[0].memref.size   = SDM_USER_FUSE_SIZE;
	op.params[1].value.a       = host_flags;
	op.params[1].value.b       = 0;

	res = TEEC_InvokeCommand(&sess, TA_SDM_FUSE_PROG_CMD_SET,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr,
			"TA_SDM_FUSE_PROG_CMD_SET: 0x%x (origin 0x%x)\n",
			res, err_origin);
		goto out_shm;
	}

	printf("\nSDM user eFuses programmed successfully (%s).\n",
	       non_volatile ? "NON-VOLATILE / eFuse burned"
			    : "virtual / cache-only");
	printf("Words programmed:\n");
	for (i = 0; i < SDM_USER_FUSE_COUNT; i++)
		printf("  Word %2u: 0x%08" PRIX32 "\n", i, fuse_data[i]);
	printf("\n");

	exit_code = 0;

out_shm:
	TEEC_ReleaseSharedMemory(&in_shm);
out_sess:
	TEEC_CloseSession(&sess);
out_ctx:
	TEEC_FinalizeContext(&ctx);
	return exit_code;
}
