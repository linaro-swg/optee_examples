// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <base_sha_ta.h>

struct base_sha {
	uint32_t algo_id;
};

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("TA created");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* TA destroyed */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void **sess_ctx)
{
	struct base_sha *sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	*sess_ctx = sess;
	DMSG("Session %p: newly allocated", *sess_ctx);
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct base_sha *sess = sess_ctx;

	/* release session */
	TEE_Free(sess);
}

static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo_id)
{
	switch (param) {
	case TA_ALG_SHA1:
		*algo_id = TEE_ALG_SHA1;
		return TEE_SUCCESS;
	case TA_ALG_SHA224:
		*algo_id = TEE_ALG_SHA224;
		return TEE_SUCCESS;
	case TA_ALG_SHA256:
		*algo_id = TEE_ALG_SHA256;
		return TEE_SUCCESS;
	case TA_ALG_SHA384:
		*algo_id = TEE_ALG_SHA384;
		return TEE_SUCCESS;
	case TA_ALG_SHA512:
		*algo_id = TEE_ALG_SHA512;
		return TEE_SUCCESS;
	case TA_ALG_SHA3_224:
		*algo_id = TEE_ALG_SHA3_224;
		return TEE_SUCCESS;
	case TA_ALG_SHA3_256:
		*algo_id = TEE_ALG_SHA3_256;
		return TEE_SUCCESS;
	case TA_ALG_SHA3_384:
		*algo_id = TEE_ALG_SHA3_384;
		return TEE_SUCCESS;
	case TA_ALG_SHA3_512:
		*algo_id = TEE_ALG_SHA3_512;
		return TEE_SUCCESS;
	case TA_ALG_SHAKE128:
		*algo_id = TEE_ALG_SHAKE128;
		return TEE_SUCCESS;
	case TA_ALG_SHAKE256:
		*algo_id = TEE_ALG_SHAKE256;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result compute_digest(void *session, uint32_t param_types,
				 TEE_Param params[4])
{
	struct base_sha *sess = NULL;
	TEE_OperationHandle op;
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	void *msg = NULL;
	size_t msg_len;
	uint32_t digest_len;
	uint32_t param;
	void *b2 = NULL;

	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	msg = params[0].memref.buffer;
	msg_len = params[0].memref.size;
	digest_len = params[1].memref.size;
	param = params[2].value.a;

	DMSG("Session %p: get compute digest", session);
	sess = session;

	if (params[1].memref.buffer && params[1].memref.size) {
		b2 = TEE_Malloc(params[1].memref.size, 0);
		if (!b2)
			goto out;
	}

	res = ta2tee_algo_id(param, &sess->algo_id);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_AllocateOperation(&op, sess->algo_id, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_DigestUpdate(op, msg, msg_len);

	res = TEE_DigestDoFinal(op, NULL, 0, b2, &digest_len);
	if (res == TEE_SUCCESS) {
		if (b2) {
			TEE_MemMove(params[1].memref.buffer, b2,
				    digest_len);
		} else {
			EMSG("Digest not genrated");
			res = TEE_ERROR_SHORT_BUFFER;
			goto out;
		}
	} else {
		EMSG("TEE_DigestDoFinal failed\n");
		goto out;
	}

	params[1].memref.size = digest_len;

	DMSG("Created digest");
	TEE_FreeOperation(op);

out:
	TEE_Free(b2);
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (cmd) {
	case CMD_COMPUTE_DIGEST:
		return compute_digest(session, param_types, params);
	default:
		EMSG("cmd id not supported");
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
