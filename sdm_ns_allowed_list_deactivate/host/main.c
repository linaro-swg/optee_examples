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
#include <sdm_ns_allowed_list_deactivate_ta.h>

static void print_banner(void)
{
	fprintf(stderr,
		"\n"
		"  ****************************************************************\n"
		"  *                       *** WARNING ***                        *\n"
		"  *                                                              *\n"
		"  *  sdm_ns_allowed_list_deactivate: about to invoke.            *\n"
		"  *                                                              *\n"
		"  *  This will DISABLE the SDM NS-FILTER whitelist.  After       *\n"
		"  *  this call ATF will no longer reject any SiP SMC FID from    *\n"
		"  *  the Non-Secure world - U-Boot, Linux, and userspace can     *\n"
		"  *  issue every SiP service that ATF supports.                  *\n"
		"  *                                                              *\n"
		"  *  This is a runtime security-policy downgrade.                *\n"
		"  *                                                              *\n"
		"  *  The whitelist is re-installed at the next OP-TEE boot       *\n"
		"  *  (cold reset / power-cycle).                                 *\n"
		"  ****************************************************************\n"
		"\n");
}

int main(int argc, char *argv[])
{
	TEEC_Result res = 0;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_UUID uuid = TA_SDM_NS_ALLOWED_LIST_DEACTIVATE_UUID;
	uint32_t err_origin = 0;

	if (argc != 1) {
		fprintf(stderr,
			"Usage: %s\n\n"
			"Deactivate the SDM Non-Secure-world allowed SiP command\n"
			"whitelist via the sdm_ns_allowed_list_deactivate TA.\n"
			"No arguments are taken.\n\n"
			"After the call succeeds, every SiP FID supported by ATF\n"
			"is callable from the Non-Secure world for the remainder\n"
			"of the current power cycle.\n",
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
		errx(1, "TEEC_OpenSession(sdm_ns_allowed_list_deactivate TA): "
		     "0x%x (origin 0x%x)", res, err_origin);
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(&sess,
				 TA_SDM_NS_ALLOWED_LIST_DEACTIVATE_CMD_APPLY,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		errx(1, "TA_SDM_NS_ALLOWED_LIST_DEACTIVATE_CMD_APPLY: "
		     "0x%x (origin 0x%x)", res, err_origin);
	}

	printf("SDM NS allowed-list deactivate: PASS\n");
	printf("  NS-FILTER is now OFF; all ATF-supported SiP FIDs are\n"
	       "  callable from the Non-Secure world until next OP-TEE boot.\n");

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
