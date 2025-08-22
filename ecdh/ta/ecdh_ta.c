// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <ecdh_ta.h>

#define ECDH_MAX_BITS   521
#define ECDH_MAX_BYTES  ((ECDH_MAX_BITS + 7) / 8)
#define ECDH_BUF_BYTES  ECDH_MAX_BYTES

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
	case TA_ECDH_ECC_CURVE_NIST_P192:
		return TEE_ECC_CURVE_NIST_P192;
	case TA_ECDH_ECC_CURVE_NIST_P224:
		return TEE_ECC_CURVE_NIST_P224;
	case TA_ECDH_ECC_CURVE_NIST_P256:
		return TEE_ECC_CURVE_NIST_P256;
	case TA_ECDH_ECC_CURVE_NIST_P384:
		return TEE_ECC_CURVE_NIST_P384;
	default:
		return TEE_CRYPTO_ELEMENT_NONE;
	}

}

static TEE_Result gen_ec_keypair(TEE_ObjectHandle *key, uint32_t curve)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t bits = curve_bits(curve);
	TEE_Attribute attrs[1] = { };

	if (!bits)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, bits, key);
	if (res)
		return res;

	TEE_InitValueAttribute(&attrs[0], TEE_ATTR_ECC_CURVE, curve, 0);
	return TEE_GenerateKey(*key, bits, attrs, 1);
}

static TEE_Result get_pub_xy(TEE_ObjectHandle key,
			     uint8_t *x, uint32_t *x_len,
			     uint8_t *y, uint32_t *y_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_ECC_PUBLIC_VALUE_X,
					   x, x_len);
	if (res)
		return res;
	res = TEE_GetObjectBufferAttribute(key, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
					   y, y_len);
	return res;
}

static TEE_Result derive_secret(TEE_ObjectHandle my_key,
				uint8_t *peer_x, uint32_t peer_x_len,
				uint8_t *peer_y, uint32_t peer_y_len,
				uint8_t *secret, uint32_t *secret_len,
				uint32_t curve)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t bits = curve_bits(curve);
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle derived = TEE_HANDLE_NULL;
	TEE_Attribute params[2] = { };

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
			     peer_x, peer_x_len);
	TEE_InitRefAttribute(&params[1], TEE_ATTR_ECC_PUBLIC_VALUE_Y,
			     peer_y, peer_y_len);

	/* Derived secret goes into a GENERIC_SECRET transient object */
	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, bits, &derived);
	if (res)
		goto out;

	TEE_DeriveKey(op, params, 2, derived);

	/* Fetch the raw shared secret bytes */
	res = TEE_GetObjectBufferAttribute(derived, TEE_ATTR_SECRET_VALUE,
					   secret, secret_len);

out:
	TEE_FreeTransientObject(derived);
	TEE_FreeOperation(op);
	return res;
}

static TEE_Result cmd_ecdh_selftest(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	const uint32_t exp_pt =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,  /* curve id in */
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_MEMREF_OUTPUT); /* shared secret out */

	uint32_t curve_ta = params[0].value.a;
	uint32_t curve = select_curve(curve_ta);
	uint32_t bits = curve_bits(curve);
	uint8_t a_x[ECDH_BUF_BYTES] = {0};
	uint8_t a_y[ECDH_BUF_BYTES] = {0};
	uint8_t b_x[ECDH_BUF_BYTES] = {0};
	uint8_t b_y[ECDH_BUF_BYTES] = {0};
	uint32_t a_x_len = ECDH_BUF_BYTES;
	uint32_t a_y_len = ECDH_BUF_BYTES;
	uint32_t b_x_len = ECDH_BUF_BYTES;
	uint32_t b_y_len = ECDH_BUF_BYTES;
	uint8_t s_a[ECDH_BUF_BYTES] = {0};
	uint8_t s_b[ECDH_BUF_BYTES] = {0};
	uint32_t s_a_len = ECDH_BUF_BYTES;
	uint32_t s_b_len = ECDH_BUF_BYTES;
	TEE_ObjectHandle key_a = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_b = TEE_HANDLE_NULL;

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!bits || curve == TEE_CRYPTO_ELEMENT_NONE)
		return TEE_ERROR_BAD_PARAMETERS;

	res = gen_ec_keypair(&key_a, curve);
	CHECK(res, "gen key A");

	res = gen_ec_keypair(&key_b, curve);
	CHECK(res, "gen key B");

	res = get_pub_xy(key_a, a_x, &a_x_len, a_y, &a_y_len);
	CHECK(res, "get A pub");

	res = get_pub_xy(key_b, b_x, &b_x_len, b_y, &b_y_len);
	CHECK(res, "get B pub");

	res = derive_secret(key_a, b_x, b_x_len, b_y, b_y_len, s_a, &s_a_len, curve);
	CHECK(res, "derive A");

	res = derive_secret(key_b, a_x, a_x_len, a_y, a_y_len, s_b, &s_b_len, curve);
	CHECK(res, "derive B");

	/* They must be identical in length and value */
	if (s_a_len != s_b_len || TEE_MemCompare(s_a, s_b, s_a_len) != 0) {
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	/* Copy to output */
	if (params[3].memref.size < s_a_len) {
		/* Tell host needed size */
		params[3].memref.size = s_a_len;
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	DMSG("curve = %"PRIu32, curve);
	DMSG("bits = %"PRIu32, bits);

	TEE_MemMove(params[3].memref.buffer, s_a, s_a_len);
	params[3].memref.size = s_a_len;
	res = TEE_SUCCESS;

out:
	TEE_FreeTransientObject(key_a);
	TEE_FreeTransientObject(key_b);
	return res;
}

/* TA entry points */

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt __unused,
				    TEE_Param params[4] __unused,
				    void **ctx __unused)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *ctx __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *ctx __unused, uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_ECDH_CMD_DERIVE_SELFTEST:
		return cmd_ecdh_selftest(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
