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

#include <sdm_get_prov_data_ta.h>

static void print_prov_data(const uint32_t *w, uint32_t actual_bytes)
{
	uint32_t num_words = actual_bytes / 4;
	uint32_t cosign_info, hash_type, hash_count;
	uint32_t wi = 0;
	int i, j;

	if (num_words < 3) {
		fprintf(stderr, "Error: provisioning data too short (%u bytes)\n",
			actual_bytes);
		return;
	}

	printf("%08X CMD_SKIPPED, PROV_STATUS\n", w[wi++]);
	printf("%08X Intel explicit key cancellation\n", w[wi++]);
	cosign_info = w[wi++];
	printf("%08X CO_SIGN, HASH_CANCELLED, HASH_VALID, HASH_COUNT, HASH_TYPE\n",
	       cosign_info);

	hash_type  = SDM_PROV_HASH_TYPE(cosign_info);
	hash_count = SDM_PROV_HASH_COUNT(cosign_info);

	if (hash_type != SDM_PROV_HASH_TYPE_SECP384R1)
		fprintf(stderr, "Note: hash type %u (expected %u=secp384r1)\n",
			hash_type, SDM_PROV_HASH_TYPE_SECP384R1);

	for (i = 0; i < (int)hash_count; i++) {
		if (wi + SDM_PROV_HASH_WORDS + 1 > num_words) {
			fprintf(stderr,
				"Warning: response truncated before hash %d\n",
				i);
			return;
		}
		for (j = 0; j < (int)SDM_PROV_HASH_WORDS; j++, wi++) {
			if (j == 0)
				printf("%08X Owner root public key hash %d\n",
				       w[wi], i);
			else
				printf("%08X\n", w[wi]);
		}
		printf("%08X Owner explicit key cancellation %d\n", w[wi++], i);
	}

	if (wi + 6 > num_words) {
		fprintf(stderr, "Warning: response truncated before tail fields\n");
		return;
	}
	printf("%08X PTS_COUNTER_BASE, PTS_COUNTER\n", w[wi++]);
	printf("%08X SVN_COUNTER_0, SVN_COUNTER_1, SVN_COUNTER_2, SVN_COUNTER_3\n",
	       w[wi++]);
	printf("%08X EFUSE_IFP_SLOT_0, EFUSE_IFP_SLOT_1, EFUSE_IFP_SLOT_2, EFUSE_IFP_SLOT_3, EFUSE_IFP_SLOT_4, EFUSE_IFP_SLOT_5\n",
	       w[wi++]);
	printf("%08X FLASH_IFP_SLOT_0, FLASH_IFP_SLOT_1, FLASH_IFP_SLOT_2, FLASH_IFP_SLOT_3, FLASH_IFP_SLOT_4, FLASH_IFP_SLOT_5\n",
	       w[wi++]);
	printf("%08X Flash Protection Counter\n", w[wi++]);
	printf("%08X OWNERSHIP_TRANSFER_MODE, OWNERSHIP_TRANSFER_OPPORTUNITIES_REMAINING\n",
	       w[wi++]);
}

int main(int argc, char *argv[])
{
	TEEC_Result res = 0;
	TEEC_Context ctx = { };
	TEEC_Session sess = { };
	TEEC_Operation op = { };
	TEEC_SharedMemory out_shm = { };
	TEEC_UUID uuid = TA_SDM_GET_PROV_DATA_UUID;
	uint32_t err_origin = 0;
	uint32_t prov[SDM_PROV_DATA_MAX_SIZE / 4];
	int exit_code = 1;

	if (argc != 1) {
		fprintf(stderr,
			"Usage: %s\n\n"
			"Retrieve and display SDM provisioning data.\n"
			"Output format matches Quartus programmer PROV_STATUS.\n",
			argv[0]);
		return 1;
	}

	memset(prov, 0, sizeof(prov));

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

	out_shm.buffer = prov;
	out_shm.size   = sizeof(prov);
	out_shm.flags  = TEEC_MEM_OUTPUT;
	res = TEEC_RegisterSharedMemory(&ctx, &out_shm);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_RegisterSharedMemory: 0x%x\n", res);
		goto out_sess;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = &out_shm;
	op.params[0].memref.size   = sizeof(prov);

	res = TEEC_InvokeCommand(&sess, TA_SDM_GET_PROV_DATA_CMD_GET,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr,
			"TA_SDM_GET_PROV_DATA_CMD_GET: 0x%x (origin 0x%x)\n",
			res, err_origin);
		goto out_shm;
	}

	printf("\nSDM Provisioning Data (%u bytes):\n\n",
	       (unsigned int)op.params[0].memref.size);
	print_prov_data(prov, (uint32_t)op.params[0].memref.size);
	printf("\n");

	exit_code = 0;

out_shm:
	TEEC_ReleaseSharedMemory(&out_shm);
out_sess:
	TEEC_CloseSession(&sess);
out_ctx:
	TEEC_FinalizeContext(&ctx);
	return exit_code;
}
