// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */


#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <sign_verify_ta.h>

struct rsa_session {
	TEE_ObjectHandle keypair;
	TEE_ObjectHandle public_key;
};

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

static TEE_Result generate_rsa_keys(struct rsa_session *sess, size_t key_sz)
{
	TEE_Result res;

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_sz,
					  &sess->keypair);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GenerateKey(sess->keypair, key_sz, NULL, 0);
	if (res != TEE_SUCCESS) {
		TEE_FreeTransientObject(sess->keypair);
		return res;
	}

	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY, key_sz,
					  &sess->public_key);
	if (res != TEE_SUCCESS) {
		TEE_FreeTransientObject(sess->keypair);
		return res;
	}

	res = TEE_CopyObjectAttributes1(sess->public_key, sess->keypair);
	if (res != TEE_SUCCESS) {
		TEE_FreeTransientObject(sess->public_key);
		TEE_FreeTransientObject(sess->keypair);
		return res;
	}

	return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
				    TEE_Param __unused params[4],
				    void **session_context)
{
	struct rsa_session *sess = TEE_Malloc(sizeof(*sess),
					      TEE_MALLOC_FILL_ZERO);

	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->keypair = TEE_HANDLE_NULL;
	sess->public_key = TEE_HANDLE_NULL;
	*session_context = sess;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_context)
{
	struct rsa_session *sess = (struct rsa_session *)session_context;

	TEE_FreeTransientObject(sess->public_key);
	TEE_FreeTransientObject(sess->keypair);
	TEE_Free(sess);
}

static TEE_Result select_algo(uint32_t sig_alg, uint32_t *algo_num)
{
	switch (sig_alg) {
	case TA_ALG_PKCS1_PSS_MGF1_SHA1:
		*algo_num = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1;
		return TEE_SUCCESS;
	case TA_ALG_PKCS1_PSS_MGF1_SHA224:
		*algo_num = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224;
		return TEE_SUCCESS;
	case TA_ALG_PKCS1_PSS_MGF1_SHA256:
		*algo_num = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256;
		return TEE_SUCCESS;
	case TA_ALG_PKCS1_PSS_MGF1_SHA384:
		*algo_num = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384;
		return TEE_SUCCESS;
	case TA_ALG_PKCS1_PSS_MGF1_SHA512:
		*algo_num = TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512;
		return TEE_SUCCESS;
	case TA_ALG_PKCS1_V1_5_SHA1:
		*algo_num = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1;
		return TEE_SUCCESS;
	case TA_ALG_PKCS1_V1_5_SHA224:
		*algo_num = TEE_ALG_RSASSA_PKCS1_V1_5_SHA224;
		return TEE_SUCCESS;
	case TA_ALG_PKCS1_V1_5_SHA256:
		*algo_num = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
		return TEE_SUCCESS;
	case TA_ALG_PKCS1_V1_5_SHA384:
		*algo_num = TEE_ALG_RSASSA_PKCS1_V1_5_SHA384;
		return TEE_SUCCESS;
	case TA_ALG_PKCS1_V1_5_SHA512:
		*algo_num = TEE_ALG_RSASSA_PKCS1_V1_5_SHA512;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static uint32_t get_hash_alg_from_sig_alg(uint32_t sig_alg)
{
	switch (sig_alg) {
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA1:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA1:
		return TEE_ALG_SHA1;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA224:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA224:
		return TEE_ALG_SHA224;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256:
		return TEE_ALG_SHA256;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA384:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA384:
		return TEE_ALG_SHA384;
	case TEE_ALG_RSASSA_PKCS1_V1_5_SHA512:
	case TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA512:
		return TEE_ALG_SHA512;
	default:
		return 0;
	}
}

static TEE_Result sign_verify(uint32_t param_types,
			      TEE_Param params[4],
			      void *session_context)
{

	struct rsa_session *sess = (struct rsa_session *)session_context;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT);
	TEE_Result res;
	TEE_OperationHandle hash_op = TEE_HANDLE_NULL;
	TEE_OperationHandle sign_op = TEE_HANDLE_NULL;
	TEE_OperationHandle verify_op = TEE_HANDLE_NULL;
	uint8_t digest[64];
	uint32_t digest_len = sizeof(digest);
	uint8_t sig[MAX_SIG_SIZE];
	uint32_t sig_len = sizeof(sig);
	uint32_t sig_alg;
	uint32_t algo_num;
	uint32_t hash_alg;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	sig_alg = params[2].value.a;
	res = select_algo(sig_alg, &algo_num);
	if (res != TEE_SUCCESS)
		return res;

	hash_alg = get_hash_alg_from_sig_alg(algo_num);
	if (hash_alg == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	void *msg = params[0].memref.buffer;
	size_t msg_len = params[0].memref.size;
	void *out = params[1].memref.buffer;
	size_t out_len = params[1].memref.size;
	size_t key_sz = params[3].value.a;

	/* Generate Key */
	DMSG("Generate Key");
	res = generate_rsa_keys(sess, key_sz);
	if (res != TEE_SUCCESS) {
		TEE_Free(sess);
		return res;
	}

	/* Compute SHA digest */
	DMSG("Prepare SHA digest");
	res = TEE_AllocateOperation(&hash_op, hash_alg, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		goto exit;
	TEE_DigestUpdate(hash_op, msg, msg_len);
	res = TEE_DigestDoFinal(hash_op, NULL, 0, digest, &digest_len);
	if (res != TEE_SUCCESS)
		goto exit;

	/* Sign the digest */
	DMSG("Signature on SHA digest");
	res = TEE_AllocateOperation(&sign_op, algo_num, TEE_MODE_SIGN, key_sz);
	if (res != TEE_SUCCESS)
		goto exit;
	res = TEE_SetOperationKey(sign_op, sess->keypair);
	if (res != TEE_SUCCESS)
		goto exit;
	res = TEE_AsymmetricSignDigest(sign_op, NULL, 0, digest,
				       digest_len, sig, &sig_len);
	if (res != TEE_SUCCESS)
		goto exit;

	/* Verify the signature */
	DMSG("Verify Signature on SHA digest");
	res = TEE_AllocateOperation(&verify_op, algo_num, TEE_MODE_VERIFY,
				    key_sz);
	if (res != TEE_SUCCESS)
		goto exit;
	res = TEE_SetOperationKey(verify_op, sess->public_key);
	if (res != TEE_SUCCESS)
		goto exit;
	res = TEE_AsymmetricVerifyDigest(verify_op, NULL, 0,
					 digest, digest_len,
					 sig, sig_len);
	if (res != TEE_SUCCESS)
		goto exit;

	if (out_len < sig_len) {
		params[1].memref.size = sig_len;
		EMSG("required sig_len = %u", params[1].memref.size);
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	memcpy(out, sig, sig_len);
	params[1].memref.size = sig_len;

exit:
	TEE_FreeOperation(verify_op);
	TEE_FreeOperation(sign_op);
	TEE_FreeOperation(hash_op);
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_context,
				      uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_RSA_SIGN_CMD_SIGN_VERIFY:
		return sign_verify(param_types, params, session_context);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
