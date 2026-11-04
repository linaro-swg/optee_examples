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
#include <sdm_ns_allowed_list_remove_ta.h>

/* ARM SMCCC bit layout (relevant subset) */
#define SMCCC_OEN_MASK		((uint32_t)0x3F << 24)
#define SMCCC_OEN_SHIFT		24
#define SMCCC_OEN_SIP		0x02
#define SMCCC_RESERVED_MASK	((uint32_t)0xFF << 16)

static int parse_hex_u32(const char *s, uint32_t *out)
{
	const char *p = s;
	char *endptr = NULL;
	unsigned long v = 0;

	if (!p || !*p)
		return -1;
	if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
		p += 2;

	errno = 0;
	v = strtoul(p, &endptr, 16);
	if (errno != 0 || endptr == p || *endptr != '\0' || v > UINT32_MAX)
		return -1;

	*out = (uint32_t)v;
	return 0;
}

static int looks_like_sip_fid(uint32_t fid)
{
	uint32_t oen = (fid & SMCCC_OEN_MASK) >> SMCCC_OEN_SHIFT;

	if (oen != SMCCC_OEN_SIP)
		return 0;
	if (fid & SMCCC_RESERVED_MASK)
		return 0;
	return 1;
}

static void print_banner(uint32_t fid)
{
	fprintf(stderr,
		"\n"
		"  ****************************************************************\n"
		"  *                       *** WARNING ***                        *\n"
		"  *                                                              *\n"
		"  *  sdm_ns_allowed_list_remove: about to invoke.                *\n"
		"  *                                                              *\n"
		"  *  Will revoke the following SiP SMC FID from the              *\n"
		"  *  Non-Secure-world allowed list (NS-FILTER):                  *\n"
		"  *                                                              *\n"
		"  *      FID = 0x%08" PRIx32 "                                   *\n"
		"  *                                                              *\n"
		"  *  After this call ATF will refuse this FID from the           *\n"
		"  *  Non-Secure world.  The whitelist is re-installed at the     *\n"
		"  *  next OP-TEE boot (cold reset / power-cycle).                *\n"
		"  ****************************************************************\n"
		"\n", fid);
}

int main(int argc, char *argv[])
{
	TEEC_Result res = 0;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_UUID uuid = TA_SDM_NS_ALLOWED_LIST_REMOVE_UUID;
	uint32_t err_origin = 0;
	uint32_t fid = 0;

	if (argc != 2) {
		fprintf(stderr,
			"Usage: %s <hex_sip_smc_fid>\n\n"
			"Remove a single SiP SMC FID from the SDM Non-Secure allowed\n"
			"list via the sdm_ns_allowed_list_remove TA.  Argument is a\n"
			"full 32-bit SiP SMC FID, NOT a raw SDM mailbox opcode.\n\n"
			"Examples:\n"
			"  %s 0x420000D3   # ALTERA_SIP_SMC_ASYNC_GET_IDCODE\n"
			"  %s 0x42000135   # ALTERA_SIP_SMC_ASYNC_FCS_CHIP_ID\n"
			"  %s 0x42000181   # ALTERA_SIP_SMC_NS_ALLOWED_LIST_DEACTIVATE\n",
			argv[0], argv[0], argv[0], argv[0]);
		return 1;
	}

	if (parse_hex_u32(argv[1], &fid) != 0)
		errx(1, "invalid hex SiP SMC FID: '%s'", argv[1]);

	if (!looks_like_sip_fid(fid))
		errx(1, "0x%08" PRIx32 " is not a well-formed SiP FID "
		     "(need OEN=0x02 and bits[23:16]=0)", fid);

	print_banner(fid);

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext: 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		TEEC_FinalizeContext(&ctx);
		errx(1, "TEEC_OpenSession(sdm_ns_allowed_list_remove TA): "
		     "0x%x (origin 0x%x)", res, err_origin);
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = fid;
	op.params[0].value.b = 0;

	res = TEEC_InvokeCommand(&sess,
				 TA_SDM_NS_ALLOWED_LIST_REMOVE_CMD_APPLY,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		errx(1, "TA_SDM_NS_ALLOWED_LIST_REMOVE_CMD_APPLY: "
		     "0x%x (origin 0x%x)", res, err_origin);
	}

	printf("SDM NS allowed-list remove: SiP FID 0x%08" PRIx32 "  PASS\n",
	       fid);
	printf("  FID 0x%08" PRIx32 " is now refused from the NS world until\n"
	       "  the next OP-TEE boot (cold reset / power-cycle).\n", fid);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return 0;
}
