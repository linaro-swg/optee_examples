// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <stdio.h>

#include <ecdsa_ta.h>

struct ecdsa {
	TEE_ObjectHandle keypair;
	TEE_ObjectHandle public_key;
	uint32_t algo_id;
	uint32_t hash_algo;
	uint32_t key_sz;
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

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param params[4],
				    void **sess_ctx)
{
	struct ecdsa *sess;

	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->keypair = TEE_HANDLE_NULL;
	sess->public_key = TEE_HANDLE_NULL;

	(void)param_types;
	(void)params;

	*sess_ctx = (void *)sess;
	DMSG("Session %p: newly allocated", *sess_ctx);
	return TEE_SUCCESS;

}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct ecdsa *sess;

	sess = (struct ecdsa *)sess_ctx;

	/* release session */
	if (sess->keypair != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->keypair);
	if (sess->public_key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->public_key);

	TEE_Free(sess);
}

static TEE_Result get_hash_algo(uint32_t algo, uint32_t *hash_algo)
{
	switch (algo) {
	case TEE_ALG_ECDSA_SHA1:
		*hash_algo = TEE_ALG_SHA1;
		return TEE_SUCCESS;
	case TEE_ALG_ECDSA_SHA224:
		*hash_algo = TEE_ALG_SHA224;
		return TEE_SUCCESS;
	case TEE_ALG_ECDSA_SHA256:
		*hash_algo = TEE_ALG_SHA256;
		return TEE_SUCCESS;
	case TEE_ALG_ECDSA_SHA384:
		*hash_algo = TEE_ALG_SHA384;
		return TEE_SUCCESS;
	case TEE_ALG_ECDSA_SHA512:
		*hash_algo = TEE_ALG_SHA512;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo_id)
{
	switch (param) {
	case TA_ALG_ECDSA_SHA1:
		*algo_id = TEE_ALG_ECDSA_SHA1;
		return TEE_SUCCESS;
	case TA_ALG_ECDSA_SHA224:
		*algo_id = TEE_ALG_ECDSA_SHA224;
		return TEE_SUCCESS;
	case TA_ALG_ECDSA_SHA256:
		*algo_id = TEE_ALG_ECDSA_SHA256;
		return TEE_SUCCESS;
	case TA_ALG_ECDSA_SHA384:
		*algo_id = TEE_ALG_ECDSA_SHA384;
		return TEE_SUCCESS;
	case TA_ALG_ECDSA_SHA512:
		*algo_id = TEE_ALG_ECDSA_SHA512;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result compute_digest(void *session, uint32_t param_types,
				 TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	struct ecdsa *sess;
	TEE_OperationHandle op;
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	void *msg = params[0].memref.buffer;
	size_t msg_len = params[0].memref.size;
	uint32_t digest_len = params[1].memref.size;
	uint32_t param = params[2].value.a;
	void *b2 = NULL;

	DMSG("Session %p: get compute digest", session);
	sess = (struct ecdsa *)session;

	if (params[1].memref.buffer && params[1].memref.size) {
		b2 = TEE_Malloc(params[1].memref.size, 0);
		if (!b2)
			goto out;
	}

	res = ta2tee_algo_id(param, &sess->algo_id);
	if (res != TEE_SUCCESS)
		return res;

	res = get_hash_algo(sess->algo_id, &sess->hash_algo);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_AllocateOperation(&op, sess->hash_algo, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		return res;

	TEE_DigestUpdate(op, msg, msg_len);

	res = TEE_DigestDoFinal(op, NULL, 0, b2, &digest_len);
	if (res == TEE_SUCCESS) {
		if (b2) {
			TEE_MemMove(params[1].memref.buffer, b2,
				    digest_len);
		}
		params[1].memref.size = digest_len;
	} else {
		DMSG("TEE_DigestDoFinal failed\n");
	}

	DMSG("Created digest");
	TEE_FreeOperation(op);
out:
	TEE_Free(b2);
	return res;
}

static TEE_Result genrate_key(void *session, uint32_t param_types)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_Result res;
	TEE_Attribute attr;
	struct ecdsa *sess = (struct ecdsa *)session;
	uint32_t key_size;
	uint32_t curve;
	uint32_t algo = sess->algo_id;

	DMSG("Session %p: compute genrate key", session);

	switch (algo) {
	case TEE_ALG_ECDSA_SHA1:
		curve = TEE_ECC_CURVE_NIST_P192;
		key_size = 192;
		break;
	case TEE_ALG_ECDSA_SHA224:
		curve = TEE_ECC_CURVE_NIST_P224;
		key_size = 224;
		break;
	case TEE_ALG_ECDSA_SHA256:
		curve = TEE_ECC_CURVE_NIST_P256;
		key_size = 256;
		break;
	case TEE_ALG_ECDSA_SHA384:
		curve = TEE_ECC_CURVE_NIST_P384;
		key_size = 384;
		break;
	case TEE_ALG_ECDSA_SHA512:
		curve = TEE_ECC_CURVE_NIST_P521;
		key_size = 521;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (sess->keypair != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->keypair);
	if (sess->public_key != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->public_key);

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, key_size,
					  &sess->keypair);
	if (res != TEE_SUCCESS)
		return res;

	TEE_InitValueAttribute(&attr, TEE_ATTR_ECC_CURVE, curve, 0);

	res = TEE_GenerateKey(sess->keypair, key_size, &attr, 1);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_PUBLIC_KEY, key_size,
					  &sess->public_key);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_CopyObjectAttributes1(sess->public_key, sess->keypair);
	if (res != TEE_SUCCESS) {
		TEE_FreeTransientObject(sess->public_key);
		TEE_FreeTransientObject(sess->keypair);
		return res;
	}

	DMSG("Key generated");
	sess->key_sz = key_size;
	return TEE_SUCCESS;
}

static TEE_Result sign_verify_digest(void *session, uint32_t param_types,
				     TEE_Param params[4])
{

	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	struct ecdsa *sess;
	TEE_OperationHandle sign_op = TEE_HANDLE_NULL;
	TEE_OperationHandle verify_op = TEE_HANDLE_NULL;
	TEE_Result res;
	void *digest;
	uint32_t digest_len;
	void *out;
	size_t out_len;
	uint8_t sig[512];
	uint32_t sig_len = sizeof(sig);

	DMSG("Session %p: Sign and Verify", session);

	sess = (struct ecdsa *)session;
	digest = params[0].memref.buffer;
	digest_len = (uint32_t)params[0].memref.size;
	out = params[1].memref.buffer;
	out_len = params[1].memref.size;

	DMSG("Sign SHA Digest\n");
	res = TEE_AllocateOperation(&sign_op, sess->algo_id,
				    TEE_MODE_SIGN, sess->key_sz);
	if (res != TEE_SUCCESS)
		goto exit;
	res = TEE_SetOperationKey(sign_op, sess->keypair);
	if (res != TEE_SUCCESS)
		goto exit;
	res = TEE_AsymmetricSignDigest(sign_op, NULL, 0, digest, digest_len,
				       sig, &sig_len);
	if (res != TEE_SUCCESS)
		goto exit;

	DMSG("Verify Signature on SHA digest");
	res = TEE_AllocateOperation(&verify_op, sess->algo_id, TEE_MODE_VERIFY,
				    sess->key_sz);
	if (res != TEE_SUCCESS)
		goto exit;
	res = TEE_SetOperationKey(verify_op, sess->public_key);
	if (res != TEE_SUCCESS)
		goto exit;
	res = TEE_AsymmetricVerifyDigest(verify_op, NULL, 0, digest,
					 digest_len, sig, sig_len);
	if (res != TEE_SUCCESS)
		goto exit;

	if (out_len < sig_len) {
		EMSG("reqired seg size is %u", params[1].memref.size);
		params[1].memref.size = sig_len;
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	TEE_MemMove(out, sig, sig_len);
	params[1].memref.size = sig_len;

exit:
	TEE_FreeOperation(sign_op);
	TEE_FreeOperation(verify_op);

	return res;

}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (cmd) {
	case CMD_COMPUTE_DIGEST:
		return compute_digest(session, param_types, params);
	case GEN_KEY:
		return genrate_key(session, param_types);
	case SIGN_VERIFY_DIGEST:
		return sign_verify_digest(session, param_types, params);
	default:
		EMSG("cmd id not supported");
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
