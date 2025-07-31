// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <sha_ta.h>

struct sha_hmac_algo {
	uint32_t algo;			/* SHA flavour */
	uint32_t mode;			/* Encode or decode */
	uint32_t key_size;		/* SHA key size in byte */
	TEE_OperationHandle op_handle;	/* SHA operation */
	TEE_ObjectHandle key_handle;	/* transient object to load the key */
};

static TEE_Result ta2tee_obj_type(uint32_t param, uint32_t *tee_obj_type)
{
	enum ta_sha_object_type obj_type = (enum ta_sha_object_type)param;

	switch (obj_type) {
	case TA_SHA_OBJ_TYPE_HMAC_SHA256:
		*tee_obj_type = TEE_TYPE_HMAC_SHA256;
		return TEE_SUCCESS;
	case TA_SHA_OBJ_TYPE_HMAC_SHA1:
		*tee_obj_type = TEE_TYPE_HMAC_SHA1;
		return TEE_SUCCESS;
	case TA_SHA_OBJ_TYPE_HMAC_SHA224:
		*tee_obj_type = TEE_TYPE_HMAC_SHA224;
		return TEE_SUCCESS;
	case TA_SHA_OBJ_TYPE_HMAC_SHA384:
		*tee_obj_type = TEE_TYPE_HMAC_SHA384;
		return TEE_SUCCESS;
	case TA_SHA_OBJ_TYPE_HMAC_SHA512:
		*tee_obj_type = TEE_TYPE_HMAC_SHA512;
		return TEE_SUCCESS;
	case TA_SHA_OBJ_TYPE_AES:
		*tee_obj_type = TEE_TYPE_AES;
		return TEE_SUCCESS;
	default:
		EMSG("Invalid mode %"PRIu32, param);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result compute_digest(void *session, uint32_t param_types,
				 TEE_Param params[4])
{
	struct sha_hmac_algo *sess = NULL;
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	void *msg = NULL;
	size_t msg_len = 0;
	uint32_t digest_len = 0;
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

	DMSG("Session %p: get compute digest", session);
	sess = session;

	if (params[1].memref.buffer && params[1].memref.size) {
		b2 = TEE_Malloc(params[1].memref.size, 0);
		if (!b2)
			goto out;
	}

	sess->algo = params[2].value.a;

	res = TEE_AllocateOperation(&sess->op_handle,
				    sess->algo,
				    TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_DigestUpdate(sess->op_handle, msg, msg_len);

	res = TEE_DigestDoFinal(sess->op_handle, NULL, 0, b2, &digest_len);
	if (res == TEE_SUCCESS)
		TEE_MemMove(params[1].memref.buffer, b2, digest_len);

	params[1].memref.size = digest_len;

out:
	TEE_Free(b2);
	return res;
}

static TEE_Result alloc_resources(void *session, uint32_t param_types,
				  TEE_Param params[4])
{
	struct sha_hmac_algo *sess = NULL;
	TEE_Attribute attr = {0};
	TEE_Result res = TEE_ERROR_GENERIC;
	char *key = NULL;
	uint32_t tee_obj_type = TEE_TYPE_HMAC_SHA256;

	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_NONE);

	/* Get context from session ID */
	DMSG("Session %p: get resources", session);
	sess = session;

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	sess->algo = params[0].value.a;

	res = ta2tee_obj_type(params[2].value.a, &tee_obj_type);
	if (res != TEE_SUCCESS)
		return res;

	sess->key_size = params[1].value.a;
	sess->mode = TEE_MODE_MAC;

	/* Free potential previous operation */
	if (sess->op_handle != TEE_HANDLE_NULL) {
		TEE_FreeOperation(sess->op_handle);
		sess->op_handle = TEE_HANDLE_NULL;
	}

	/* Allocate operation: SHA, mode and size from params */
	res = TEE_AllocateOperation(&sess->op_handle,
				    sess->algo,
				    sess->mode,
				    sess->key_size * 8);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation");
		goto err;
	}

	/* Free potential previous transient object */
	if (sess->key_handle != TEE_HANDLE_NULL) {
		TEE_FreeTransientObject(sess->key_handle);
		sess->key_handle = TEE_HANDLE_NULL;
	}

	/* Allocate transient object according to target key size */
	res = TEE_AllocateTransientObject(tee_obj_type,
					  sess->key_size * 8,
					  &sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate transient object");
		goto err;
	}

	key = TEE_Malloc(sess->key_size, 0);
	if (!key) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}

	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, sess->key_size);

	res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
	TEE_Free(key);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_PopulateTransientObject failed, %#"PRIx32, res);
		goto err;
	}

	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %#"PRIx32, res);
		goto err;
	}

	return TEE_SUCCESS;

err:
	TEE_FreeOperation(sess->op_handle);
	sess->op_handle = TEE_HANDLE_NULL;

	TEE_FreeTransientObject(sess->key_handle);
	sess->key_handle = TEE_HANDLE_NULL;

	return res;
}

/*
 * Process command TA_SHA_CMD_SET_KEY. API in sha_ta.h
 */
static TEE_Result set_sha_key(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	struct sha_hmac_algo *sess = NULL;
	TEE_Attribute attr = {0};
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t key_sz = 0;
	char *key = NULL;

	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/* Get ciphering context from session ID */
	DMSG("Session %p: load key material", session);
	sess = session;

	if (sess->key_handle == TEE_HANDLE_NULL ||
	    sess->op_handle == TEE_HANDLE_NULL) {
		EMSG("Operation not properly initialized.");
		return TEE_ERROR_BAD_STATE;
	}

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
		EMSG("TEE_PopulateTransientObject failed, %#"PRIx32, res);
		return res;
	}

	TEE_ResetOperation(sess->op_handle);
	res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetOperationKey failed %#"PRIx32, res);
		return res;
	}

	return res;
}

/*
 * Process command TA_SHA_CMD_SET_IV. API in sha_ta.h
 */
static TEE_Result reset_sha_iv(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	struct sha_hmac_algo *sess = NULL;
	size_t iv_sz = 0;
	char *iv = NULL;

	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/* Get context from session ID */
	DMSG("Session %p: reset initial vector", session);
	sess = session;

	if (sess->op_handle == TEE_HANDLE_NULL) {
		EMSG("Operation not properly initialized.");
		return TEE_ERROR_BAD_STATE;
	}

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	iv = params[0].memref.buffer;
	iv_sz = params[0].memref.size;

	/*
	 * Init operation with the initialization vector.
	 */
	TEE_MACInit(sess->op_handle, iv, iv_sz);

	return TEE_SUCCESS;
}

static TEE_Result sha_update_op(void *session, uint32_t param_types,
				TEE_Param params[4])
{
	struct sha_hmac_algo *sess = NULL;
	TEE_Result res = TEE_ERROR_OUT_OF_MEMORY;
	void *message = NULL;
	size_t message_sz = 0;
	uint32_t hmac_len = 0;
	void *b2 = NULL;

	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	DMSG("Session %p: sha update operation", session);
	sess = session;

	if (sess->op_handle == TEE_HANDLE_NULL) {
		EMSG("Operation not properly initialized.");
		return TEE_ERROR_BAD_STATE;
	}

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	message = params[0].memref.buffer;
	message_sz = params[0].memref.size;
	hmac_len = (uint32_t)params[1].memref.size;

	if (params[1].memref.buffer && params[1].memref.size) {
		b2 = TEE_Malloc(params[1].memref.size, 0);
		if (!b2)
			goto out;
	}

	TEE_MACUpdate(sess->op_handle, message, message_sz);

	res = TEE_MACComputeFinal(sess->op_handle, message, message_sz,
				  b2, &hmac_len);

	if (res == TEE_SUCCESS)
		TEE_MemMove(params[1].memref.buffer, b2, hmac_len);

	params[1].memref.size = hmac_len;

out:
	TEE_Free(b2);
	return res;
}

static TEE_Result compare_hmac_sha_algo(void *session, uint32_t param_types,
					TEE_Param params[4])
{
	struct sha_hmac_algo *sess = NULL;
	void *message = NULL;
	size_t message_sz = 0;
	void *hmac_buff = NULL;
	uint32_t hmac_len = 0;

	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	DMSG("Session %p: Compare HMAC SHA", session);
	sess = session;

	if (sess->op_handle == TEE_HANDLE_NULL) {
		EMSG("Operation not properly initialized.");
		return TEE_ERROR_BAD_STATE;
	}

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	message = params[0].memref.buffer;
	message_sz = params[0].memref.size;
	hmac_buff = params[1].memref.buffer;
	hmac_len = (uint32_t)params[1].memref.size;

	TEE_MACUpdate(sess->op_handle, message, message_sz);

	return TEE_MACCompareFinal(sess->op_handle, message, message_sz,
				   hmac_buff, hmac_len);
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
	/*
	 * Allocate and init for the session.
	 * The address of the structure is used as session ID for
	 * the client.
	 */
	struct sha_hmac_algo *sess = TEE_Malloc(sizeof(*sess), 0);

	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = sess;
	DMSG("Session %p: newly allocated", *session);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	/* Get context from session ID */
	DMSG("Session %p: release session", session);
	struct sha_hmac_algo *sess = session;

	/* Release the session resources */
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
	case TA_SHA_CMD_PREPARE:
		return alloc_resources(session, param_types, params);
	case TA_SHA_CMD_SET_KEY:
		return set_sha_key(session, param_types, params);
	case TA_SHA_CMD_SET_IV:
		return reset_sha_iv(session, param_types, params);
	case TA_SHA_CMD_COMPUTE_MAC:
		return sha_update_op(session, param_types, params);
	case TA_SHA_CMD_COMPARE_MAC:
		return compare_hmac_sha_algo(session, param_types, params);
	case TA_SHA_CMD_COMPUTE_DIGEST:
		return compute_digest(session, param_types, params);
	default:
		EMSG("Command ID 0x%"PRIx32" is not supported", cmd);
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
