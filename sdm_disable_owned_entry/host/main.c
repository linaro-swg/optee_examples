// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>

#include <sdm_disable_owned_entry_ta.h>

static void usage(const char *prog, int exit_code)
{
	FILE *fp = (exit_code == 0) ? stdout : stderr;

	fprintf(fp,
		"Usage: %s [--non-volatile]\n"
		"\n"
		"Permanently disable transition of the device to the OWNED\n"
		"life-cycle state via the sdm_disable_owned_entry TA.\n"
		"\n"
		"      --non-volatile  *** PERMANENTLY BURN THE PHYSICAL eFUSE ***\n"
		"                      Disables physical fuse programming of the\n"
		"                      owner public-key root hash.  The device will\n"
		"                      remain permanently configured in PRODUCTION\n"
		"                      state and can NEVER transition to OWNED.\n"
		"                      Default (omit this flag) is virtual /\n"
		"                      cache-only fusing (reversible across reset).\n"
		"  -h, --help          show this help and exit\n"
		"\n"
		"Exit status: 0 = accepted, 1 = rejected or error\n",
		prog);
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
	TEEC_UUID uuid = TA_SDM_DISABLE_OWNED_ENTRY_UUID;
	uint32_t err_origin = 0;
	uint32_t host_flags = 0;
	bool non_volatile = false;
	int c = 0;
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

	if (optind != argc) {
		fprintf(stderr, "%s: unexpected argument: %s\n",
			argv[0], argv[optind]);
		usage(argv[0], 1);
	}

	if (non_volatile) {
		host_flags |= SDM_DEO_HOST_FLAG_NON_VOLATILE;
		fprintf(stderr,
			"\n"
			"  ****************************************************************\n"
			"  *                       *** WARNING ***                        *\n"
			"  *                                                              *\n"
			"  *  --non-volatile selected.                                    *\n"
			"  *                                                              *\n"
			"  *  This command will permanently disable physical fuse         *\n"
			"  *  programming of the owner public-key root hash.              *\n"
			"  *                                                              *\n"
			"  *  The device shall remain permanently configured in           *\n"
			"  *  PRODUCTION state and can never transition to OWNED.         *\n"
			"  *                                                              *\n"
			"  *  This action is IRREVERSIBLE.                                *\n"
			"  ****************************************************************\n"
			"\n");
	} else {
		printf("\n"
			"  ****************************************************************\n"
			"  *                                                              *\n"
			"  *  Mode: virtual / cache-only                                  *\n"
			"  *                                                              *\n"
			"  *  This command will permanently disable physical fuse         *\n"
			"  *  programming of the owner public-key root hash.              *\n"
			"  *                                                              *\n"
			"  *  The device shall remain permanently configured in           *\n"
			"  *  PRODUCTION state and can never transition to OWNED.         *\n"
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

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = host_flags;
	op.params[0].value.b = 0;

	res = TEEC_InvokeCommand(&sess, TA_SDM_DISABLE_OWNED_ENTRY_CMD_APPLY,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr,
			"TA_SDM_DISABLE_OWNED_ENTRY_CMD_APPLY: 0x%x (origin 0x%x)\n",
			res, err_origin);
		goto out_sess;
	}

	printf("SDM disable-owned-entry applied (%s)  PASS\n",
	       non_volatile ? "NON-VOLATILE / eFuse burned"
			    : "virtual / cache-only");
	exit_code = 0;

out_sess:
	TEEC_CloseSession(&sess);
out_ctx:
	TEEC_FinalizeContext(&ctx);
	return exit_code;
}
