// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_sdm_svc.h>
#include <sdm_crypt_ta.h>

struct crypt_sess_ctx {
	TEE_TASessionHandle pta_sess;
};


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("sdm_crypt TA: create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("sdm_crypt TA: destroy");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void **sess_ctx)
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	const TEE_UUID pta_uuid = PTA_SDM_SVC_UUID;
	struct crypt_sess_ctx *ctx = NULL;
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	uint32_t pta_pt = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = TEE_Malloc(sizeof(*ctx), TEE_MALLOC_FILL_ZERO);
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = TEE_OpenTASession(&pta_uuid, TEE_TIMEOUT_INFINITE,
				TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE),
				pta_params, &ctx->pta_sess, &pta_origin);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_OpenTASession(PTA_SDM_SVC) failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		TEE_Free(ctx);
		return res;
	}

	pta_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
				 TEE_PARAM_TYPE_NONE,
				 TEE_PARAM_TYPE_NONE,
				 TEE_PARAM_TYPE_NONE);
	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_GET_VERSION, pta_pt,
				  pta_params, &pta_origin);
	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_GET_VERSION failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		TEE_CloseTASession(ctx->pta_sess);
		TEE_Free(ctx);
		return res;
	}

	if (pta_params[0].value.a < PTA_SDM_SVC_API_VERSION) {
		EMSG("PTA API version %u too old (need %u)",
		     pta_params[0].value.a, PTA_SDM_SVC_API_VERSION);
		TEE_CloseTASession(ctx->pta_sess);
		TEE_Free(ctx);
		return TEE_ERROR_NOT_SUPPORTED;
	}

	IMSG("sdm_crypt TA: session opened, PTA API v%u",
	     pta_params[0].value.a);
	*sess_ctx = ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct crypt_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return;

	TEE_CloseTASession(ctx->pta_sess);
	TEE_Free(ctx);
	IMSG("sdm_crypt TA: session closed");
}


static TEE_Result check_common_hdr(const struct sdos_hdr *hdr,
				   uint32_t expected_magic)
{
	uint32_t pad_len = 0;

	if (hdr->magic != expected_magic) {
		EMSG("SDOS hdr: bad magic 0x%08x (expected 0x%08x)",
		     hdr->magic, expected_magic);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (hdr->hdr_pad != SDOS_HDR_PAD_MAGIC) {
		EMSG("SDOS hdr: bad hdr_pad 0x%08x (expected 0x%08x)",
		     hdr->hdr_pad, SDOS_HDR_PAD_MAGIC);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (hdr->data_len < SDOS_MIN_DATA_LEN ||
	    hdr->data_len > SDOS_MAX_DATA_LEN) {
		EMSG("SDOS hdr: data_len %u out of range [%u..%u]",
		     hdr->data_len, SDOS_MIN_DATA_LEN, SDOS_MAX_DATA_LEN);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (hdr->data_len % 32U) {
		EMSG("SDOS hdr: data_len %u not multiple of 32",
		     hdr->data_len);
		return TEE_ERROR_BAD_FORMAT;
	}

	pad_len = SDOS_FLAGS_PAD_LEN(hdr->flags);
	if (pad_len > 31U) {
		EMSG("SDOS hdr: pad_len %u > 31", pad_len);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (pad_len >= hdr->data_len) {
		EMSG("SDOS hdr: pad_len %u >= data_len %u (no payload)",
		     pad_len, hdr->data_len);
		return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

static TEE_Result validate_encrypt(const struct sdos_hdr *hdr,
				   size_t in_size, size_t out_size)
{
	TEE_Result res = check_common_hdr(hdr, SDOS_ENCRYPT_IN_MAGIC);
	size_t expected_in = 0;
	size_t expected_out = 0;
	size_t i = 0;

	if (res != TEE_SUCCESS)
		return res;

	expected_in = (size_t)SDOS_HDR_SIZE + hdr->data_len;
	if (in_size != expected_in) {
		EMSG("encrypt: in_size %zu != hdr (%u + %u = %zu)",
		     in_size, (unsigned)SDOS_HDR_SIZE, hdr->data_len,
		     expected_in);
		return TEE_ERROR_BAD_FORMAT;
	}

	expected_out = expected_in + (size_t)SDOS_HMAC_SIZE;
	if (out_size < expected_out) {
		EMSG("encrypt: out_size %zu < %zu (hdr + data + hmac)",
		     out_size, expected_out);
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* IV must be all-zero on encrypt input - SDM fills it in the output */
	for (i = 0; i < sizeof(hdr->iv) / sizeof(hdr->iv[0]); i++) {
		if (hdr->iv[i] != 0) {
			EMSG("encrypt: iv[%zu] = 0x%08x must be 0", i,
			     hdr->iv[i]);
			return TEE_ERROR_BAD_FORMAT;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result validate_decrypt(const struct sdos_hdr *hdr,
				   size_t in_size, size_t out_size)
{
	TEE_Result res = check_common_hdr(hdr, SDOS_ENCRYPT_OUT_MAGIC);
	size_t expected_in = 0;
	size_t expected_out = 0;

	if (res != TEE_SUCCESS)
		return res;

	expected_in = (size_t)SDOS_HDR_SIZE + hdr->data_len +
		      (size_t)SDOS_HMAC_SIZE;
	if (in_size != expected_in) {
		EMSG("decrypt: in_size %zu != hdr + data + hmac (%zu)",
		     in_size, expected_in);
		return TEE_ERROR_BAD_FORMAT;
	}

	/* PTA returns the full SDOS structure: hdr + plaintext + padding */
	expected_out = (size_t)SDOS_HDR_SIZE + hdr->data_len;
	if (out_size < expected_out) {
		EMSG("decrypt: out_size %zu < %zu (hdr + data)",
		     out_size, expected_out);
		return TEE_ERROR_SHORT_BUFFER;
	}

	return TEE_SUCCESS;
}


static TEE_Result do_sdos_crypt(struct crypt_sess_ctx *ctx,
				uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE);
	void *ns_in = NULL;
	void *ns_out = NULL;
	size_t in_size = 0;
	size_t out_size = 0;
	uint32_t direction = 0;
	void *local_in = NULL;
	const struct sdos_hdr *hdr = NULL;
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	if (param_types != exp_pt) {
		EMSG("bad param types 0x%08x", param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	direction = params[0].value.a;
	ns_in     = params[1].memref.buffer;
	in_size   = params[1].memref.size;
	ns_out    = params[2].memref.buffer;
	out_size  = params[2].memref.size;

	if (direction != TA_SDM_CRYPT_DIR_DECRYPT &&
	    direction != TA_SDM_CRYPT_DIR_ENCRYPT) {
		EMSG("bad direction %u", direction);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!ns_in || !in_size || !ns_out || !out_size) {
		EMSG("null/zero memref: in=%p (%zu) out=%p (%zu)",
		     ns_in, in_size, ns_out, out_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (in_size < (size_t)SDOS_HDR_SIZE) {
		EMSG("in_size %zu < SDOS_HDR_SIZE (%u)", in_size,
		     (unsigned)SDOS_HDR_SIZE);
		return TEE_ERROR_BAD_FORMAT;
	}

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  ns_in, in_size);
	if (res != TEE_SUCCESS) {
		EMSG("input memref not readable: in=%p size=%zu res=0x%08x",
		     ns_in, in_size, res);
		return res;
	}

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_WRITE |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  ns_out, out_size);
	if (res != TEE_SUCCESS) {
		EMSG("output memref not writable: out=%p size=%zu res=0x%08x",
		     ns_out, out_size, res);
		return res;
	}

	local_in = TEE_Malloc(in_size, 0);
	if (!local_in) {
		EMSG("alloc local_in (%zu) failed", in_size);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_MemMove(local_in, ns_in, in_size);

	hdr = (const struct sdos_hdr *)local_in;

	if (direction == TA_SDM_CRYPT_DIR_ENCRYPT)
		res = validate_encrypt(hdr, in_size, out_size);
	else
		res = validate_decrypt(hdr, in_size, out_size);

	if (res != TEE_SUCCESS) {
		TEE_MemFill(local_in, 0, in_size);
		TEE_Free(local_in);
		return res;
	}

	DMSG("sdm_crypt: %s validated (in=%zu out=%zu data_len=%u pad=%u)",
	     direction == TA_SDM_CRYPT_DIR_ENCRYPT ? "encrypt" : "decrypt",
	     in_size, out_size, hdr->data_len,
	     SDOS_FLAGS_PAD_LEN(hdr->flags));

	pta_params[0].value.a = direction;
	pta_params[1].memref.buffer = local_in;
	pta_params[1].memref.size   = in_size;
	pta_params[2].memref.buffer = ns_out;
	pta_params[2].memref.size   = out_size;

	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_SDM_SDOS_CRYPT, exp_pt,
				  pta_params, &pta_origin);

	params[2].memref.size = pta_params[2].memref.size;

	TEE_MemFill(local_in, 0, in_size);
	TEE_Free(local_in);

	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_SDM_SDOS_CRYPT failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		return res;
	}

	DMSG("sdm_crypt: %s OK, out=%zu bytes",
	     direction == TA_SDM_CRYPT_DIR_ENCRYPT ? "encrypt" : "decrypt",
	     (size_t)params[2].memref.size);
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct crypt_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return TEE_ERROR_BAD_STATE;

	switch (cmd_id) {
	case TA_SDM_CRYPT_CMD_RUN:
		return do_sdos_crypt(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
