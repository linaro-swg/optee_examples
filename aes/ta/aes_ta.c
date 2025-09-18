// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 */
#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <aes_ta.h>

#define AES128_KEY_BIT_SIZE		128
#define AES128_KEY_BYTE_SIZE		(AES128_KEY_BIT_SIZE / 8)
#define AES256_KEY_BIT_SIZE		256
#define AES256_KEY_BYTE_SIZE		(AES256_KEY_BIT_SIZE / 8)

/*
 * Ciphering context: each opened session relates to a cipehring operation.
 * - configure the AES flavour from a command.
 * - load key from a command (here the key is provided by the REE)
 * - reset init vector (here IV is provided by the REE)
 * - cipher a buffer frame (here input and output buffers are non-secure)
 */
struct aes_cipher {
	uint32_t algo;			/* AES flavour */
	uint32_t mode;			/* Encode or decode */
	uint32_t key_size;		/* AES key size in byte */
	TEE_OperationHandle op_handle;	/* AES ciphering operation */
	TEE_ObjectHandle key_handle;	/* transient object to load the key */
};

/*
 * Few routines to convert IDs from TA API into IDs from OP-TEE.
 */
static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo)
{
	switch (param) {
	case TA_AES_ALGO_ECB:
		*algo = TEE_ALG_AES_ECB_NOPAD;
		return TEE_SUCCESS;
	case TA_AES_ALGO_CBC:
		*algo = TEE_ALG_AES_CBC_NOPAD;
		return TEE_SUCCESS;
	case TA_AES_ALGO_CTR:
		*algo = TEE_ALG_AES_CTR;
		return TEE_SUCCESS;
	case TA_AES_ALGO_CCM:
		*algo = TEE_ALG_AES_CCM;
		return TEE_SUCCESS;
	case TA_AES_ALGO_GCM:
		*algo = TEE_ALG_AES_GCM;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid algo %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_key_size(uint32_t param, uint32_t *key_size)
{
	switch (param) {
	case AES128_KEY_BYTE_SIZE:
	case AES256_KEY_BYTE_SIZE:
		*key_size = param;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid key size %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
static TEE_Result ta2tee_mode_id(uint32_t param, uint32_t *mode)
{
	switch (param) {
	case TA_AES_MODE_ENCODE:
		*mode = TEE_MODE_ENCRYPT;
		return TEE_SUCCESS;
	case TA_AES_MODE_DECODE:
		*mode = TEE_MODE_DECRYPT;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid mode %u", param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

/*
 * Process command TA_AES_CMD_PREPARE. API in aes_ta.h
 *
 * Allocate resources required for the ciphering operation.
 * During ciphering operation, when expect client can:
 * - update the key materials (provided by client)
 * - reset the initial vector (provided by client)
 * - cipher an input buffer into an output buffer (provided by client)
 */
static TEE_Result alloc_resources(void *session, uint32_t param_types,
				  TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess = NULL;
	TEE_Attribute attr = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	char *key = NULL;

	/* Get ciphering context from session ID */
	DMSG("Session %p: get ciphering resources", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = ta2tee_algo_id(params[0].value.a, &sess->algo);
	if (res != TEE_SUCCESS)
		return res;

	res = ta2tee_key_size(params[1].value.a, &sess->key_size);
	if (res != TEE_SUCCESS)
		return res;

	res = ta2tee_mode_id(params[2].value.a, &sess->mode);
	if (res != TEE_SUCCESS)
		return res;

	/*
	 * Ready to allocate the resources which are:
	 * - an operation handle, for an AES ciphering of given configuration
	 * - a transient object that will be use to load the key materials
	 *   into the AES ciphering operation.
	 */

	/* Free potential previous operation */
	TEE_FreeOperation(sess->op_handle);

	/* Allocate operation: AES/CTR, mode and size from params */
	res = TEE_AllocateOperation(&sess->op_handle,
				    sess->algo,
				    sess->mode,
				    sess->key_size * 8);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		sess->op_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/* Free potential previous transient object */
	TEE_FreeTransientObject(sess->key_handle);

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES,
					  sess->key_size * 8,
					  &sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		sess->key_handle = TEE_HANDLE_NULL;
		goto err;
	}

	/*
	 * When loading a key in the cipher session, set_aes_key()
	 * will reset the operation and load a key. But we cannot
	 * reset and operation that has no key yet (GPD TEE Internal
	 * Core API Specification – Public Release v1.1.1, section
	 * 6.2.5 TEE_ResetOperation). In consequence, we will load a
	 * dummy key in the operation so that operation can be reset
	 * when updating the key.
	 */
	key = TEE_Malloc(sess->key_size, 0);
	if (!key) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, sess->key_size);

	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	TEE_Free(key);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		goto err;
	}

	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		goto err;
	}

	return res;

err:
	TEE_FreeOperation(sess->op_handle);
	sess->op_handle = TEE_HANDLE_NULL;

	TEE_FreeTransientObject(sess->key_handle);
	sess->key_handle = TEE_HANDLE_NULL;

	return res;
}

/*
 * Process command TA_AES_CMD_SET_KEY. API in aes_ta.h
 */
static TEE_Result set_aes_key(void *session, uint32_t param_types,
			      TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess = NULL;
	TEE_Attribute attr = { };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t key_sz = 0;
	char *key = NULL;

	/* Get ciphering context from session ID */
	DMSG("Session %p: load key material", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	key = params[0].memref.buffer;
	key_sz = params[0].memref.size;

	if (key_sz != sess->key_size) {
		EMSG("Wrong key size %" PRIu32 ", expect %" PRIu32 " bytes",
		     key_sz, sess->key_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * Load the key material into the configured operation
	 * - create a secret key attribute with the key material
	 *   TEE_InitRefAttribute()
	 * - reset transient object and load attribute data
	 *   TEE_ResetTransientObject()
	 *   TEE_PopulateTransientObject()
	 * - load the key (transient object) into the ciphering operation
	 *   TEE_SetOperationKey()
	 *
	 * TEE_SetOperationKey() requires operation to be in "initial state".
	 * We can use TEE_ResetOperation() to reset the operation but this
	 * API cannot be used on operation with key(s) not yet set. Hence,
	 * when allocating the operation handle, we load a dummy key.
	 * Thus, set_key sequence always reset then set key on operation.
	 */

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_sz);

	TEE_ResetTransientObject(sess->key_handle);
	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %x", res);
		return res;
	}

	TEE_ResetOperation(sess->op_handle);
	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %x", res);
		return res;
	}

	return res;
}

/*
 * Process command TA_AES_CMD_SET_IV. API in aes_ta.h
 */
static TEE_Result reset_aes_iv(void *session, uint32_t param_types,
			       TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess = NULL;
	size_t iv_sz = 0;
	char *iv = NULL;

	/* Get ciphering context from session ID */
	DMSG("Session %p: reset initial vector", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	iv = params[0].memref.buffer;
	iv_sz = params[0].memref.size;

	/*
	 * Init cipher operation with the initialization vector.
	 */
	TEE_CipherInit(sess->op_handle, iv, iv_sz);

	return TEE_SUCCESS;
}

/*
 * Process command TA_AES_CMD_CIPHER. API in aes_ta.h
 */
static TEE_Result cipher_buffer(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);
	struct aes_cipher *sess = NULL;

	/* Get ciphering context from session ID */
	DMSG("Session %p: cipher buffer", session);
	sess = (struct aes_cipher *)session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[1].memref.size < params[0].memref.size) {
		EMSG("Bad sizes: in %d, out %d", params[0].memref.size,
						 params[1].memref.size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (sess->op_handle == TEE_HANDLE_NULL)
		return TEE_ERROR_BAD_STATE;

	/*
	 * Process ciphering operation on provided buffers
	 */
	return TEE_CipherUpdate(sess->op_handle,
				params[0].memref.buffer, params[0].memref.size,
				params[1].memref.buffer, &params[1].memref.size);
}

static TEE_Result auth_enc_op(void *session, uint32_t param_types, TEE_Param params[4])
{
	struct aes_cipher *sess = session;
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	uint32_t tag_len = 0;
	uint32_t out_len = 0;
	void *in_buf = NULL;
	size_t in_sz = 0;
	bool encrypt = true;
	void *b2 = NULL;
	void *b3 = NULL;
	uint8_t nonce[12] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B
	};
	const uint32_t expected_pt =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_INOUT);

	if (param_types != expected_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	tag_len = params[3].memref.size;
	out_len = params[1].memref.size;
	in_buf = params[0].memref.buffer;
	in_sz = params[0].memref.size;
	encrypt = (params[2].value.a != 0);

	if (params[1].memref.buffer && params[1].memref.size) {
		b2 = TEE_Malloc(params[1].memref.size, 0);
		if (!b2)
			goto out;
	}

	DMSG("Initializing an Authentication Encryption operation");

	res = TEE_AEInit(sess->op_handle, nonce, sizeof(nonce),
			 tag_len * 8, 0, in_sz);

	if (res != TEE_SUCCESS)
		goto out;

	if (encrypt) {
		if (params[3].memref.buffer && params[3].memref.size) {
			b3 = TEE_Malloc(params[3].memref.size, 0);
			if (!b3) {
				res = TEE_ERROR_OUT_OF_MEMORY;
				goto out;
			}
		}
		DMSG("AE Encryption");
		res = TEE_AEEncryptFinal(sess->op_handle,
					 in_buf, in_sz,
					 b2, &out_len,
					 b3, &tag_len);

		if (res == TEE_SUCCESS) {
			if (b2) {
				TEE_MemMove(params[1].memref.buffer, b2,
					    out_len);
			}
			if (b3) {
				TEE_MemMove(params[3].memref.buffer, b3,
					    tag_len);
			}

			params[1].memref.size = out_len;
			params[3].memref.size = tag_len;
		} else {
			EMSG("TEE_AEEncryptFinal failed with %#"PRIx32, res);
		}
	} else {

		DMSG("AE Decryption");
		res = TEE_AEDecryptFinal(sess->op_handle,
					 in_buf, in_sz,
					 b2, &out_len,
					 params[3].memref.buffer,
					 tag_len);
		if (res == TEE_SUCCESS) {

			if (b2) {
				TEE_MemMove(params[1].memref.buffer, b2,
					    out_len);
			}

			params[1].memref.size = out_len;
		} else {
			EMSG("TEE_AEDecryptFinal failed with %#"PRIx32, res);
		}
	}
out:
	TEE_Free(b2);
	TEE_Free(b3);

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
				    void __unused **session)
{
	struct aes_cipher *sess = NULL;

	/*
	 * Allocate and init ciphering materials for the session.
	 * The address of the structure is used as session ID for
	 * the client.
	 */
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("Session %p: newly allocated", *session);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct aes_cipher *sess = NULL;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", session);
	sess = (struct aes_cipher *)session;

	/* Release all remaining session resources */
	TEE_FreeTransientObject(sess->key_handle);
	TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
					uint32_t cmd,
					uint32_t param_types,
					TEE_Param params[4])
{
	switch (cmd) {
	case TA_AES_CMD_PREPARE:
		return alloc_resources(session, param_types, params);
	case TA_AES_CMD_SET_KEY:
		return set_aes_key(session, param_types, params);
	case TA_AES_CMD_SET_IV:
		return reset_aes_iv(session, param_types, params);
	case TA_AES_CMD_CIPHER:
		return cipher_buffer(session, param_types, params);
	case TA_AES_CMD_AUTHENC:
		return auth_enc_op(session, param_types, params);
	default:
		EMSG("Command ID 0x%x is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
