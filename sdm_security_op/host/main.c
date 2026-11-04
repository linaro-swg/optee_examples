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

#include <sdm_security_op_ta.h>

static void usage(const char *prog, int exit_code)
{
	FILE *fp = (exit_code == 0) ? stdout : stderr;

	fprintf(fp,
		"Usage: %s <hex_option_word> [--non-volatile]\n"
		"\n"
		"Apply the SDM EFUSE user security option word via OP-TEE TA.\n"
		"\n"
		"  <hex_option_word>   32-bit security option bitmap, hex with or\n"
		"                      without 0x prefix.  Bit 31 is IGNORED here\n"
		"                      (test mode is controlled by --non-volatile).\n"
		"      --non-volatile  *** PERMANENTLY BURN THE PHYSICAL eFUSE ***\n"
		"                      Clears the SDM test bit; the requested\n"
		"                      fuses are written and CANNOT be reversed.\n"
		"                      Default (omit this flag) is test/cache-only.\n"
		"  -h, --help          show this help and exit\n"
		"\n"
		"SDM_SECOPT_* bits:\n"
		"  bit  0  FIRMWARE_JOINT_SIGNING   (0x%08x)\n"
		"  bit  1  AES_KEY_UPDATE_MODE      (0x%08x)\n"
		"  bit  2  JTAG_DISABLE             (0x%08x)  [requires bit 12]\n"
		"  bit  3  HPS_DEBUG_DISABLE        (0x%08x)\n"
		"  bit  4  VIRTUAL_EFUSE_DISABLE    (0x%08x)  [must be EXCLUSIVE]\n"
		"  bit  5  HPS_ZEROIZATION          (0x%08x)\n"
		"  bit  6  FPGA_ZEROIZATION         (0x%08x)\n"
		"  bit  7  PUF_AES_KEY_DISABLE      (0x%08x)\n"
		"  bit  8  BBRAM_AES_KEY_DISABLE    (0x%08x)\n"
		"  bit  9  EFUSE_AES_KEY_DISABLE    (0x%08x)\n"
		"  bit 10  PUF_ENROLLMENT_DISABLE   (0x%08x)\n"
		"  bit 11  SECURE_CLOCK_ONLY        (0x%08x)\n"
		"  bit 12  CRC_ENABLE               (0x%08x)\n"
		"  bit 16  ALIASL1_DISABLE          (0x%08x)\n"
		"  bit 17  DISABLE_BETA_MODE        (0x%08x)\n"
		"\n"
		"Exit status: 0 = accepted, 1 = rejected or error\n",
		prog,
		SDM_SECOPT_FIRMWARE_JOINT_SIGNING,
		SDM_SECOPT_AES_KEY_UPDATE_MODE,
		SDM_SECOPT_JTAG_DISABLE,
		SDM_SECOPT_HPS_DEBUG_DISABLE,
		SDM_SECOPT_VIRTUAL_EFUSE_DISABLE,
		SDM_SECOPT_HPS_ZEROIZATION,
		SDM_SECOPT_FPGA_ZEROIZATION,
		SDM_SECOPT_PUF_AES_KEY_DISABLE,
		SDM_SECOPT_BBRAM_AES_KEY_DISABLE,
		SDM_SECOPT_EFUSE_AES_KEY_DISABLE,
		SDM_SECOPT_PUF_ENROLLMENT_DISABLE,
		SDM_SECOPT_SECURE_CLOCK_ONLY,
		SDM_SECOPT_CRC_ENABLE,
		SDM_SECOPT_ALIASL1_DISABLE,
		SDM_SECOPT_DISABLE_BETA_MODE);
	exit(exit_code);
}

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

static void print_decoded(uint32_t opt)
{
	printf("Requested option_word = 0x%08" PRIx32 "\n", opt);
	if (opt & SDM_SECOPT_FIRMWARE_JOINT_SIGNING)
		printf("  bit  0  SDM_SECOPT_FIRMWARE_JOINT_SIGNING\n");
	if (opt & SDM_SECOPT_AES_KEY_UPDATE_MODE)
		printf("  bit  1  SDM_SECOPT_AES_KEY_UPDATE_MODE\n");
	if (opt & SDM_SECOPT_JTAG_DISABLE)
		printf("  bit  2  SDM_SECOPT_JTAG_DISABLE          [requires bit 12]\n");
	if (opt & SDM_SECOPT_HPS_DEBUG_DISABLE)
		printf("  bit  3  SDM_SECOPT_HPS_DEBUG_DISABLE\n");
	if (opt & SDM_SECOPT_VIRTUAL_EFUSE_DISABLE)
		printf("  bit  4  SDM_SECOPT_VIRTUAL_EFUSE_DISABLE [must be EXCLUSIVE]\n");
	if (opt & SDM_SECOPT_HPS_ZEROIZATION)
		printf("  bit  5  SDM_SECOPT_HPS_ZEROIZATION\n");
	if (opt & SDM_SECOPT_FPGA_ZEROIZATION)
		printf("  bit  6  SDM_SECOPT_FPGA_ZEROIZATION\n");
	if (opt & SDM_SECOPT_PUF_AES_KEY_DISABLE)
		printf("  bit  7  SDM_SECOPT_PUF_AES_KEY_DISABLE\n");
	if (opt & SDM_SECOPT_BBRAM_AES_KEY_DISABLE)
		printf("  bit  8  SDM_SECOPT_BBRAM_AES_KEY_DISABLE\n");
	if (opt & SDM_SECOPT_EFUSE_AES_KEY_DISABLE)
		printf("  bit  9  SDM_SECOPT_EFUSE_AES_KEY_DISABLE\n");
	if (opt & SDM_SECOPT_PUF_ENROLLMENT_DISABLE)
		printf("  bit 10  SDM_SECOPT_PUF_ENROLLMENT_DISABLE\n");
	if (opt & SDM_SECOPT_SECURE_CLOCK_ONLY)
		printf("  bit 11  SDM_SECOPT_SECURE_CLOCK_ONLY\n");
	if (opt & SDM_SECOPT_CRC_ENABLE)
		printf("  bit 12  SDM_SECOPT_CRC_ENABLE\n");
	if (opt & SDM_SECOPT_ALIASL1_DISABLE)
		printf("  bit 16  SDM_SECOPT_ALIASL1_DISABLE\n");
	if (opt & SDM_SECOPT_DISABLE_BETA_MODE)
		printf("  bit 17  SDM_SECOPT_DISABLE_BETA_MODE\n");
	if (opt & SDM_SECOPT_TEST_MODE)
		printf("  bit 31  SDM_SECOPT_TEST_MODE  (ignored — controlled by --non-volatile)\n");
	if (opt & ~SDM_SECOPT_VALID_MASK)
		printf("  (reserved bits set: 0x%08" PRIx32 " - will be REJECTED)\n",
		       opt & ~SDM_SECOPT_VALID_MASK);
}

static int pre_validate(uint32_t opt_clean)
{
	if (opt_clean == 0) {
		fprintf(stderr,
			"\nERROR: option word is empty after stripping TEST_MODE.\n"
			"At least one SDM_SECOPT_* bit must be set.\n");
		return 1;
	}
	if (opt_clean & ~SDM_SECOPT_FUNCTIONAL_MASK) {
		fprintf(stderr,
			"\nERROR: reserved bits set: 0x%08" PRIx32
			" (allowed mask 0x%08" PRIx32 ").\n",
			opt_clean & ~SDM_SECOPT_FUNCTIONAL_MASK,
			SDM_SECOPT_FUNCTIONAL_MASK);
		return 1;
	}
	if ((opt_clean & SDM_SECOPT_VIRTUAL_EFUSE_DISABLE) &&
	    (opt_clean != SDM_SECOPT_VIRTUAL_EFUSE_DISABLE)) {
		fprintf(stderr,
			"\nERROR: SDM_SECOPT_VIRTUAL_EFUSE_DISABLE (bit 4) "
			"must be the only option in the command.\n"
			"Got option_word=0x%08" PRIx32 ", extra bits=0x%08" PRIx32 ".\n",
			opt_clean,
			opt_clean & ~SDM_SECOPT_VIRTUAL_EFUSE_DISABLE);
		return 1;
	}
	if ((opt_clean & SDM_SECOPT_JTAG_DISABLE) &&
	    !(opt_clean & SDM_SECOPT_CRC_ENABLE)) {
		fprintf(stderr,
			"\nERROR: SDM_SECOPT_JTAG_DISABLE (bit 2) requires "
			"SDM_SECOPT_CRC_ENABLE (bit 12).\n"
			"Add 0x%08" PRIx32 " to your option word.\n",
			SDM_SECOPT_CRC_ENABLE);
		return 1;
	}
	return 0;
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
	TEEC_UUID uuid = TA_SDM_SECURITY_OP_UUID;
	uint32_t err_origin = 0;
	uint32_t opt = 0;
	uint32_t opt_clean = 0;
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

	if (optind + 1 != argc) {
		fprintf(stderr,
			"%s: expected exactly one <hex_option_word> argument\n",
			argv[0]);
		usage(argv[0], 1);
	}

	if (parse_hex_u32(argv[optind], &opt) != 0)
		errx(1, "invalid hex option word: '%s'", argv[optind]);

	print_decoded(opt);

	opt_clean = opt & ~SDM_SECOPT_TEST_MODE;
	if (pre_validate(opt_clean) != 0)
		return 1;

	if (non_volatile) {
		host_flags |= SDM_SECOPT_HOST_FLAG_NON_VOLATILE;
		fprintf(stderr,
			"\n"
			"  ************************************************************\n"
			"  *  WARNING: --non-volatile selected.                       *\n"
			"  *  The SDM will PERMANENTLY burn the requested eFuse bits  *\n"
			"  *  for option_word=0x%08" PRIx32 ".                       *\n"
			"  *  This action is IRREVERSIBLE.                            *\n"
			"  ************************************************************\n"
			"\n",
			opt_clean);
	} else {
		printf("\nMode: test/cache-only (PTA forces SDM_SECOPT_TEST_MODE=1)\n"
		       "      No physical fuse will be burned.\n\n");
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
					 TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = opt_clean;
	op.params[0].value.b = 0;
	op.params[1].value.a = host_flags;
	op.params[1].value.b = 0;

	res = TEEC_InvokeCommand(&sess, TA_SDM_SECURITY_OP_CMD_APPLY,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr,
			"TA_SDM_SECURITY_OP_CMD_APPLY: 0x%x (origin 0x%x)\n",
			res, err_origin);
		goto out_sess;
	}

	printf("SDM security option applied (%s): option_word=0x%08" PRIx32 "  PASS\n",
	       non_volatile ? "NON-VOLATILE / eFuse burned"
			    : "test / cache-only",
	       opt_clean);
	exit_code = 0;

out_sess:
	TEEC_CloseSession(&sess);
out_ctx:
	TEEC_FinalizeContext(&ctx);
	return exit_code;
}
