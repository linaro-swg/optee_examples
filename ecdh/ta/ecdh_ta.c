// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <ecdh_ta.h>

#define CHECK(res, msg) \
	do { if ((res) != TEE_SUCCESS) { EMSG(msg); TEE_Panic((res)); } } while (0)

static uint32_t curve_bits(uint32_t curve_id)
{
	switch (curve_id) {
	case TEE_ECC_CURVE_NIST_P192:
		return 192;
	case TEE_ECC_CURVE_NIST_P224:
		return 224;
	case TEE_ECC_CURVE_NIST_P256:
		return 256;
	case TEE_ECC_CURVE_NIST_P384:
		return 384;
	default:
		return 0;
	}
}

static uint32_t select_curve(uint32_t curve_id)
{
	switch (curve_id) {
	case TA_ECC_CURVE_NIST_P192:
		return TEE_ECC_CURVE_NIST_P192;
	case TA_ECC_CURVE_NIST_P224:
		return TEE_ECC_CURVE_NIST_P224;
	case TA_ECC_CURVE_NIST_P256:
		return TEE_ECC_CURVE_NIST_P256;
	case TA_ECC_CURVE_NIST_P384:
		return TEE_ECC_CURVE_NIST_P384;
	default:
		return 0;
	}

}

static TEE_Result gen_ec_keypair(TEE_ObjectHandle *key, uint32_t curve)
{
	TEE_Result res;
	uint32_t bits = curve_bits(curve);
	TEE_Attribute attrs[1];

	if (!bits)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, bits, key);
	if (res)
		return res;

	TEE_InitValueAttribute(&attrs[0], TEE_ATTR_ECC_CURVE, curve, 0);
	res = TEE_GenerateKey(*key, bits, attrs, 1);
	return res;
}

static TEE_Result get_pub_xy(TEE_ObjectHandle key,
			     uint8_t *x, uint32_t *x_len,
			     uint8_t *y, uint32_t *y_len)
{
	TEE_Result res;

	res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_ECC_PUBLIC_VALUE_X,
					   x, x_len);
	if (res)
		return res;
	res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
					   y, y_len);
	return res;
}

static TEE_Result derive_secret(TEE_ObjectHandle my_key,
				const uint8_t *peer_x, uint32_t peer_x_len,
				const uint8_t *peer_y, uint32_t peer_y_len,
				uint8_t *secret, uint32_t *secret_len,
				uint32_t curve)
{
	TEE_Result res;
	uint32_t bits = curve_bits(curve);
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle derived = TEE_HANDLE_NULL;
	TEE_Attribute params[2];

	if (!bits)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Allocate operation for ECDH derive */
	res = TEE_AllocateOperation(&op, TEE_ALG_ECDH_DERIVE_SHARED_SECRET,
				    TEE_MODE_DERIVE, bits);
	if (res)
		return res;

	res = TEE_SetOperationKey(op, my_key);
	if (res)
		goto out;

	/* Provide peer public coordinates as derivation parameters */
	TEE_InitRefAttribute(&params[0], TEE_ATTR_ECC_PUBLIC_VALUE_X,
			     (void *)peer_x, peer_x_len);
	TEE_InitRefAttribute(&params[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			     (void *)peer_y, peer_y_len);

	/* Derived secret goes into a GENERIC_SECRET transient object */
	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, bits, &derived);
	if (res)
		goto out;

	TEE_DeriveKey(op, params, 2, derived);

	/* Fetch the raw shared secret bytes */
	res = TEE_GetObjectBufferAttribute(derived, TEE_ATTR_SECRET_VALUE,
					   secret, secret_len);

out:
	if (derived != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(derived);
	if (op != TEE_HANDLE_NULL)
		TEE_FreeOperation(op);
	return res;
}

static TEE_Result cmd_ecdh_selftest(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	const uint32_t exp_pt =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,  /* curve id in,secret len out */
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_MEMREF_OUTPUT); /* shared secret out */

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t curve_ta = params[0].value.a;
	uint32_t curve = select_curve(curve_ta);
	uint32_t bits = curve_bits(curve);

	DMSG("curve = %u", curve);
	DMSG("bits = %u", bits);

	if (!bits)
		return TEE_ERROR_BAD_PARAMETERS;

	TEE_ObjectHandle keyA = TEE_HANDLE_NULL, keyB = TEE_HANDLE_NULL;

	res = gen_ec_keypair(&keyA, curve);
	CHECK(res, "gen key A");

	res = gen_ec_keypair(&keyB, curve);
	CHECK(res, "gen key B");

	/* Export A.pub and B.pub */
	uint8_t Ax[ECDH_BUF_BYTES] = {0}, Ay[ECDH_BUF_BYTES] = {0};
	uint8_t Bx[ECDH_BUF_BYTES] = {0}, By[ECDH_BUF_BYTES] = {0};
	uint32_t Ax_len = ECDH_BUF_BYTES, Ay_len = ECDH_BUF_BYTES;
	uint32_t Bx_len = ECDH_BUF_BYTES, By_len = ECDH_BUF_BYTES;

	res = get_pub_xy(keyA, Ax, &Ax_len, Ay, &Ay_len);
	CHECK(res, "get A pub");

	res = get_pub_xy(keyB, Bx, &Bx_len, By, &By_len);
	CHECK(res, "get B pub");

	/* Derive from A with B.pub and from B with A.pub */
	uint8_t Sa[ECDH_BUF_BYTES] = {0}, Sb[ECDH_BUF_BYTES] = {0};
	uint32_t Sa_len = ECDH_BUF_BYTES, Sb_len = ECDH_BUF_BYTES;

	res = derive_secret(keyA, Bx, Bx_len, By, By_len, Sa, &Sa_len, curve);
	CHECK(res, "derive A");

	res = derive_secret(keyB, Ax, Ax_len, Ay, Ay_len, Sb, &Sb_len, curve);
	CHECK(res, "derive B");

	/* They must be identical in length and value */
	if (Sa_len != Sb_len || TEE_MemCompare(Sa, Sb, Sa_len) != 0) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	/* Copy to output */
	if (params[3].memref.size < Sa_len) {
		/* Tell host needed size */
		params[0].value.b = Sa_len;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	TEE_MemMove(params[3].memref.buffer, Sa, Sa_len);
	params[0].value.b = Sa_len;
	params[3].memref.size = Sa_len;
	res = TEE_SUCCESS;

out:
	if (keyA != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(keyA);
	if (keyB != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(keyB);
	return res;
}

/* TA entry points */

TEE_Result TA_CreateEntryPoint(void) { return TEE_SUCCESS; }
void TA_DestroyEntryPoint(void) {}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param params[4], void **ctx)
{
	(void)pt; (void)params; (void)ctx;
	return TEE_SUCCESS;
}
void TA_CloseSessionEntryPoint(void *ctx) { (void)ctx; }

TEE_Result TA_InvokeCommandEntryPoint(void *ctx, uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	(void)ctx;

	switch (cmd_id) {
	case TA_ECDH_CMD_DERIVE_SELFTEST:
		return cmd_ecdh_selftest(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
