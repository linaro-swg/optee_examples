// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tee_client_api.h>
#include <sdm_efuse_write_disable_ta.h>

static void print_banner(void)
{
	fprintf(stderr,
		"\n"
		"  ****************************************************************\n"
		"  *                     ***** TEST MODE *****                    *\n"
		"  *                                                              *\n"
		"  *  sdm_efuse_write_disable: about to invoke.                   *\n"
		"  *                                                              *\n"
		"  *  After this call the SDM will refuse all subsequent          *\n"
		"  *  physical eFuse-write commands; any further fuse             *\n"
		"  *  programming will be redirected to virtual (cache-only)      *\n"
		"  *  fuses.                                                      *\n"
		"  *                                                              *\n"
		"  *  This state holds for the current power cycle only and is    *\n"
		"  *  cleared on the next cold reset / power-off.                 *\n"
		"  *                                                              *\n"
		"  *  Within this session the transition is one-way - eFuse       *\n"
		"  *  writes cannot be re-enabled without a power-cycle.          *\n"
		"  ****************************************************************\n"
		"\n");
}

int main(int argc, char *argv[])
{
	TEEC_Result res = 0;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_UUID uuid = TA_SDM_EFUSE_WRITE_DISABLE_UUID;
	uint32_t err_origin = 0;

	if (argc != 1) {
		fprintf(stderr,
			"Usage: %s\n\n"
			"Put the SDM into eFuse-write-disabled (test) mode via the\n"
			"sdm_efuse_write_disable TA.  No arguments are taken.\n\n"
			"After the call succeeds, subsequent physical eFuse writes\n"
			"are refused and any fuse programming is redirected to\n"
			"virtual (cache-only) fuses for the remainder of the power\n"
			"cycle.\n",
			argv[0]);
		return 1;
	}

	print_banner();

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext: 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		TEEC_FinalizeContext(&ctx);
		errx(1, "TEEC_OpenSession(sdm_efuse_write_disable TA): "
		     "0x%x (origin 0x%x)", res, err_origin);
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, TA_SDM_EFUSE_WRITE_DISABLE_CMD_APPLY,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		errx(1, "TA_SDM_EFUSE_WRITE_DISABLE_CMD_APPLY: 0x%x (origin 0x%x)",
		     res, err_origin);
	}

	printf("SDM eFuse write-disable: PASS\n");
	printf("  SDM is now in test mode - subsequent fuse writes go to\n"
	       "  virtual (cache-only) fuses; power-cycle to restore.\n");

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
