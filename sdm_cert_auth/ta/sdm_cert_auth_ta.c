// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026, Intel Corporation
 */

#include <inttypes.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pta_sdm_svc.h>
#include <sdm_cert_auth_ta.h>

struct cert_sess_ctx {
	TEE_TASessionHandle pta_sess;
};


TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("sdm_cert_auth TA: create");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("sdm_cert_auth TA: destroy");
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
	struct cert_sess_ctx *ctx = NULL;
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

	IMSG("sdm_cert_auth TA: session opened, PTA API v%u",
	     pta_params[0].value.a);
	*sess_ctx = ctx;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	struct cert_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return;

	TEE_CloseTASession(ctx->pta_sess);
	TEE_Free(ctx);
	IMSG("sdm_cert_auth TA: session closed");
}


static TEE_Result validate_vab_header(const struct sdm_cert_hdr *hdr,
				      size_t cert_size)
{
	size_t max_data_sz = 0;

	if (hdr->cert_magic_num != SDM_CERT_MAGIC_NUM) {
		EMSG("cert hdr: bad cert_magic_num 0x%08x (expected 0x%08x)",
		     hdr->cert_magic_num, SDM_CERT_MAGIC_NUM);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (hdr->vab_cert_magic_num != SDM_CERT_MAGIC_NUM) {
		EMSG("cert hdr: bad vab_cert_magic_num 0x%08x (expected 0x%08x)",
		     hdr->vab_cert_magic_num, SDM_CERT_MAGIC_NUM);
		return TEE_ERROR_BAD_FORMAT;
	}

	if (hdr->cert_data_sz == 0) {
		EMSG("cert hdr: cert_data_sz is 0");
		return TEE_ERROR_BAD_FORMAT;
	}

	max_data_sz = cert_size - (size_t)VAB_CERT_HEADER_SIZE;
	if ((size_t)hdr->cert_data_sz > max_data_sz) {
		EMSG("cert hdr: cert_data_sz %u > buffer remaining %zu",
		     hdr->cert_data_sz, max_data_sz);
		return TEE_ERROR_BAD_FORMAT;
	}

	DMSG("cert hdr OK: cert_data_sz=%u cert_ver=%u cert_type=0x%x",
	     hdr->cert_data_sz, hdr->cert_ver, hdr->cert_type);
	return TEE_SUCCESS;
}


static TEE_Result do_send_cert(struct cert_sess_ctx *ctx,
			       uint32_t param_types, TEE_Param params[4])
{
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						TEE_PARAM_TYPE_VALUE_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	void *ns_cert = NULL;
	size_t cert_size = 0;
	void *local_cert = NULL;
	const struct sdm_cert_hdr *hdr = NULL;
	TEE_Param pta_params[4] = { };
	uint32_t pta_origin = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	/* Zero the host's output before any return; populated by the PTA */
	params[1].value.a = 0;
	params[1].value.b = 0;

	if (param_types != exp_pt) {
		EMSG("bad param types 0x%08x", param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ns_cert   = params[0].memref.buffer;
	cert_size = params[0].memref.size;

	if (!ns_cert || cert_size == 0 || cert_size > SDM_CERT_MAX_SIZE) {
		EMSG("bad cert memref: buf=%p size=%zu (max %u)",
		     ns_cert, cert_size, SDM_CERT_MAX_SIZE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cert_size & 0x3U) {
		EMSG("cert size %zu not 4-byte aligned", cert_size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (cert_size < (size_t)VAB_CERT_HEADER_SIZE) {
		EMSG("cert size %zu < VAB_CERT_HEADER_SIZE (%u)",
		     cert_size, (unsigned)VAB_CERT_HEADER_SIZE);
		return TEE_ERROR_BAD_FORMAT;
	}

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ |
					  TEE_MEMORY_ACCESS_ANY_OWNER,
					  ns_cert, cert_size);
	if (res != TEE_SUCCESS) {
		EMSG("cert memref not readable: buf=%p size=%zu res=0x%08x",
		     ns_cert, cert_size, res);
		return res;
	}

	local_cert = TEE_Malloc(cert_size, 0);
	if (!local_cert) {
		EMSG("alloc local_cert (%zu) failed", cert_size);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	TEE_MemMove(local_cert, ns_cert, cert_size);

	hdr = (const struct sdm_cert_hdr *)local_cert;
	res = validate_vab_header(hdr, cert_size);
	if (res != TEE_SUCCESS) {
		/* Wipe the rejected cert before returning the heap memory */
		TEE_MemFill(local_cert, 0, cert_size);
		TEE_Free(local_cert);
		return res;
	}

	DMSG("sdm_cert_auth: validated (%zu bytes), forwarding to PTA",
	     cert_size);

	pta_params[0].memref.buffer = local_cert;
	pta_params[0].memref.size   = cert_size;
	/* pta_params[1] (VALUE_OUTPUT) is zero-initialised */

	res = TEE_InvokeTACommand(ctx->pta_sess, TEE_TIMEOUT_INFINITE,
				  PTA_CMD_SDM_SEND_CERT, exp_pt,
				  pta_params, &pta_origin);

	/* Propagate SDM mailbox result to the host even on errors */
	params[1].value.a = pta_params[1].value.a;
	params[1].value.b = pta_params[1].value.b;

	TEE_MemFill(local_cert, 0, cert_size);
	TEE_Free(local_cert);

	if (res != TEE_SUCCESS) {
		EMSG("PTA_CMD_SDM_SEND_CERT failed: 0x%08x (origin 0x%x)",
		     res, pta_origin);
		return res;
	}

	DMSG("sdm_cert_auth: SDM response mbox_err=0x%08x detail=0x%08x",
	     params[1].value.a, params[1].value.b);
	return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types,
				      TEE_Param params[4])
{
	struct cert_sess_ctx *ctx = sess_ctx;

	if (!ctx)
		return TEE_ERROR_BAD_STATE;

	switch (cmd_id) {
	case TA_SDM_CERT_AUTH_CMD_SEND:
		return do_send_cert(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}
