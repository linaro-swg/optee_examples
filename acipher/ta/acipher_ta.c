// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <inttypes.h>

#include <tee_internal_api.h>

#include <acipher_ta.h>

struct acipher {
	TEE_ObjectHandle key;
};

static TEE_Result cmd_gen_key(struct acipher *state, uint32_t pt,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	uint32_t key_size;
	TEE_ObjectHandle key;
	const uint32_t key_type = TEE_TYPE_RSA_KEYPAIR;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	key_size = params[0].value.a;

	res = TEE_AllocateTransientObject(key_type, key_size, &key);
	if (res) {
		EMSG("TEE_AllocateTransientObject(%#" PRIx32 ", %" PRId32 "): %#"
		     PRIx32, key_type, key_size, res);
		return res;
	}

	res = TEE_GenerateKey(key, key_size, NULL, 0);
	if (res) {
		EMSG("TEE_GenerateKey(%" PRId32 "): %#" PRIx32,
		     key_size, res);
		TEE_FreeTransientObject(key);
		return res;
	}

	TEE_FreeTransientObject(state->key);
	state->key = key;
	return TEE_SUCCESS;
}

static TEE_Result select_algo(uint32_t param, uint32_t *algo)
{
	switch (param) {
	case TA_ALG_PKCS1_V1_5:
		*algo = TEE_ALG_RSAES_PKCS1_V1_5;
		return TEE_SUCCESS;
	case TA_ALG_OAEP_MGF1_SHA1:
		*algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA1;
		return TEE_SUCCESS;
	case TA_ALG_OAEP_MGF1_SHA224:
		*algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA224;
		return TEE_SUCCESS;
	case TA_ALG_OAEP_MGF1_SHA256:
		*algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256;
		return TEE_SUCCESS;
	case TA_ALG_OAEP_MGF1_SHA384:
		*algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA384;
		return TEE_SUCCESS;
	case TA_ALG_OAEP_MGF1_SHA512:
		*algo = TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA512;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid algo %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result cmd_enc(struct acipher *state, uint32_t pt,
			  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res;
	const void *inbuf;
	uint32_t inbuf_len;
	void *outbuf;
	uint32_t outbuf_len;
	uint32_t alg_num;
	TEE_OperationHandle op;
	TEE_ObjectInfo key_info;
	uint32_t encrypt;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_VALUE_INPUT);

	if (pt != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;
	if (!state->key)
		return TEE_ERROR_BAD_STATE;

	res = TEE_GetObjectInfo1(state->key, &key_info);
	if (res) {
		EMSG("TEE_GetObjectInfo1: %#" PRIx32, res);
		return res;
	}

	inbuf = params[0].memref.buffer;
	inbuf_len = params[0].memref.size;
	outbuf = params[1].memref.buffer;
	outbuf_len = params[1].memref.size;

	res = select_algo(params[3].value.a, &alg_num);
	if (res != TEE_SUCCESS)
		return res;

	if (params[2].value.a)
		encrypt = TEE_MODE_ENCRYPT;
	else
		encrypt = TEE_MODE_DECRYPT;

	res = TEE_AllocateOperation(&op, alg_num, encrypt,
				    key_info.keySize);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_ENCRYPT, %#"
		     PRIx32 ", %" PRId32 "): %#" PRIx32,
		     alg_num, key_info.keySize, res);
		return res;
	}

	res = TEE_SetOperationKey(op, state->key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		goto out;
	}

	if (encrypt == TEE_MODE_ENCRYPT) {
		res = TEE_AsymmetricEncrypt(op, NULL, 0, inbuf,
					    inbuf_len, outbuf, &outbuf_len);
		if (res) {
			EMSG("TEE_AsymmetricEncrypt(%" PRId32 ", %"
			     PRId32 "): %#" PRIx32, inbuf_len,
			     params[1].memref.size, res);
		}
	} else {
		res = TEE_AsymmetricDecrypt(op, NULL, 0, inbuf, inbuf_len,
					    outbuf, &outbuf_len);
		if (res) {
			EMSG("TEE_AsymmetricDecrypt(%" PRId32 ", %"
			     PRId32 "): %#" PRIx32, inbuf_len,
			     params[1].memref.size, res);
		}
	}
	params[1].memref.size = outbuf_len;

out:
	TEE_FreeOperation(op);
	return res;

}

TEE_Result TA_CreateEntryPoint(void)
{
	/* Nothing to do */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Nothing to do */
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
					TEE_Param __unused params[4],
					void **session)
{
	struct acipher *state;

	/*
	 * Allocate and init state for the session.
	 */
	state = TEE_Malloc(sizeof(*state), 0);
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	state->key = TEE_HANDLE_NULL;

	*session = state;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct acipher *state = session;

	TEE_FreeTransientObject(state->key);
	TEE_Free(state);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd) {
	case TA_ACIPHER_CMD_GEN_KEY:
		return cmd_gen_key(session, param_types, params);
	case TA_ACIPHER_CMD_ENCRYPT:
		return cmd_enc(session, param_types, params);
	default:
		EMSG("Command ID %#" PRIx32 " is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
