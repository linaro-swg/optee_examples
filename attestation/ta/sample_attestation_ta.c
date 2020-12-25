// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Elias von Däniken
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <sample_attestation_ta.h>
#include <pta_attestation.h>

#define HASH_SIZE 32
#define HASH_ALGO TEE_ALG_SHA256
#define SIGN_ALGO TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256

#define RSA_KEY_SIZE_BITS 2048
#define RSA_KEY_SIZE_BYTES (RSA_KEY_SIZE_BITS / 8)
#define ATT_CERT_SIZE (4 * HASH_SIZE + RSA_KEY_SIZE_BYTES)

static const TEE_UUID pta_attestation_uuid = ATTESTATION_UUID;

/*
 * State of the TA instance. Contains the attestation key (AK) which is unique
 * to every instance. And it also contains the secure counter. He is the POC
 * application.
 */
struct ta_state {
	TEE_ObjectHandle key;
	union counter_union {
		uint32_t u;
		uint8_t c[4];
	} counter;
};

/*
 * Convert an unsigned integer to ASN1
 */
static TEE_Result uint_to_asn1(uint8_t type,
								uint8_t *payload, size_t payload_len,
								uint8_t *dst, size_t *dst_len)
{
	union useful_size {
		size_t thesize;
		uint8_t thebytes[sizeof(size_t)];
	} s;
	int index = 0;
	bool leading_zeros = false;

	s.thesize = payload_len;

	// first byte is the type
	dst[index] = type;
	index += 1;

	// if its an integer and the first bit is set,
	// it needs leading zeros because asn1 is signed
	if (type == 0x02 && (payload[0] & 0x80)) {
		leading_zeros = true;
		s.thesize += 1;
	}

	// calculate how many bytes are used in union useful_size
	uint8_t byte_cnt = 0;

	for (size_t i = 0; i < sizeof(size_t); i++)
		if (s.thebytes[i])
			byte_cnt += 1;

	// if the payload is bigger than 0x80 then more than one byte is necessary
	// to describe the length of the following payload
	if (s.thesize >= 0x80) {
		dst[index] = 0x80 | byte_cnt; // how many bytes following to describe the length
		index += 1;
		for (size_t i = 0; i < byte_cnt; i++) {
			dst[index] = s.thebytes[i];
			index += 1;
		}
	} else {
		dst[index] = s.thebytes[0];
		index += 1;
	}

	// add the zeros in front of the unsigned number (if necessary)
	if (leading_zeros) {
		dst[index] = 0x00;
		index += 1;
	}

	// copy the payload
	for (size_t i = 0; i < payload_len; i++) {
		dst[index] = payload[i];
		index += 1;
	}

	// return the effective length of the encoding
	*dst_len = index;

	return TEE_SUCCESS;
}

/*
 * Convert a public key to ASN1 (DER)
 * Only tested with 2048 bit keys
 */
static TEE_Result pub_key_to_asn1(uint8_t *mod, size_t mod_len,
									uint8_t *exp, size_t exp_len,
									uint8_t *dst, size_t *dst_len)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t header_bytes = 4;
	size_t encoded_mod_len;
	size_t encoded_exp_len;

	// convert the mod
	res = uint_to_asn1(0x02, mod, mod_len,
						dst+header_bytes, &encoded_mod_len);
	if (res)
		return res;
	// convert the exp
	res = uint_to_asn1(0x02, exp, exp_len,
						dst+header_bytes+encoded_mod_len, &encoded_exp_len);
	if (res)
		return res;

	// encode the header
	dst[0] = 0x30; // indicates seq
	dst[1] = 0x82; // indicates that the size is two bytes big
	dst[2] = (encoded_mod_len+encoded_exp_len)/0x100; // sizebyte 1
	dst[3] = (encoded_mod_len+encoded_exp_len)%0x100; // sizebyte 2

	*dst_len = header_bytes + encoded_mod_len + encoded_exp_len;
	return TEE_SUCCESS;
}

static TEE_Result create_digest(const uint8_t *in, uint32_t in_len,
								uint8_t *out, uint32_t *out_len)
{
	TEE_Result res;
	TEE_OperationHandle handle = (TEE_OperationHandle) NULL;
	uint32_t message_len = in_len;
	void *message = NULL;
	uint32_t digest_len = HASH_SIZE;
	void *digest = NULL;

	// its important to alloctate this memory this way
	message = TEE_Malloc(message_len, 0);
	digest = TEE_Malloc(digest_len, 0);
	TEE_MemMove(message, in, in_len);
	message_len = in_len;

	res = TEE_AllocateOperation(&handle, HASH_ALGO, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS) {
		IMSG("ERROR: Digest allocate\n");
		return res;
	}

	res = TEE_DigestDoFinal(handle, message, in_len, digest, &digest_len);
	if (res == TEE_ERROR_SHORT_BUFFER) {
		IMSG("ERROR: Digest final short buffer\n");
		return res;
	}

	memcpy(out, digest, digest_len);
	*out_len = digest_len;

	TEE_FreeOperation(handle);
	TEE_Free(message);
	TEE_Free(digest);
	return res;
}

/*
 * This function does the actual attestation of the TA instance. It
 * prepares the attestation key (AK) and the user data. Then calls the
 * attestation PTA for the attestation certificate. This certificate proves
 * the genuinty of the TA. The certificate is returned to the Normal world
 * and then sent to the verifier.
 */
static TEE_Result attestation(struct ta_state *state, uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG("has been called");
	TEE_Result res = TEE_ERROR_GENERIC;

	// check the input parameters
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	// check that a valid rsa key is present
	if (!state->key)
		return TEE_ERROR_BAD_STATE;

	// prepare the mem for the rsa components
	uint32_t bin_modulus_len = RSA_KEY_SIZE_BYTES;
	uint8_t bin_modulus[bin_modulus_len];
	uint32_t bin_exponent_len = 3;
	uint8_t bin_exponent[bin_exponent_len];

	// get the binary representation of the rsa modulus
	res = TEE_GetObjectBufferAttribute(state->key, TEE_ATTR_RSA_MODULUS,
										bin_modulus, &bin_modulus_len);
	if (res)
		return res;

	// get the binary representation of the rsa public exponent
	res = TEE_GetObjectBufferAttribute(state->key,
										TEE_ATTR_RSA_PUBLIC_EXPONENT,
										bin_exponent, &bin_exponent_len);
	if (res)
		return res;

	// allocate mem for the asn1 encoded pub key
	size_t out_pub_key_len = bin_modulus_len + bin_exponent_len + 11;
	uint8_t out_pub_key[out_pub_key_len];

	// encode the pub key to asn1
	res = pub_key_to_asn1(bin_modulus, bin_modulus_len,
							bin_exponent, bin_exponent_len,
							out_pub_key, &out_pub_key_len);
	if (res)
		return res;

	// ------------ Call PTA ---------
	TEE_TASessionHandle session = TEE_HANDLE_NULL;
	uint32_t ret_origin = 0;
	uint32_t pta_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											TEE_PARAM_TYPE_MEMREF_INPUT,
											TEE_PARAM_TYPE_MEMREF_OUTPUT,
											TEE_PARAM_TYPE_NONE);

	TEE_Param pta_params[TEE_NUM_PARAMS];
	uint8_t att_cert[ATT_CERT_SIZE];

	// prepare the parameters for the pta
	pta_params[0].memref.buffer = out_pub_key;
	pta_params[0].memref.size = out_pub_key_len;
	pta_params[1].memref.buffer = params[0].memref.buffer;
	pta_params[1].memref.size  = params[0].memref.size;
	pta_params[2].memref.buffer = att_cert;
	pta_params[2].memref.size = sizeof(att_cert);

	// ------------ Open Session to PTA ---------
	res = TEE_OpenTASession(&pta_attestation_uuid, 0, 0, NULL, &session,
				&ret_origin);
	if (res != TEE_SUCCESS)
		return res;

	// ------------ Invoke command at PTA (get_cert) ---------
	res = TEE_InvokeTACommand(session, 0, ATTESTATION_CMD_GET_CERT,
								pta_param_types, pta_params, &ret_origin);
	if (res != TEE_SUCCESS)
		return res;

	// ------------ Close Session to PTA ---------
	TEE_CloseTASession(session);

	// Prepare the output buffers
	memcpy(params[1].memref.buffer, out_pub_key,  out_pub_key_len);
	params[1].memref.size = out_pub_key_len;
	memcpy(params[2].memref.buffer, att_cert,  sizeof(att_cert));
	params[2].memref.size = sizeof(att_cert);

	return TEE_SUCCESS;
}

/*
 * This function generates the attestation key (AK), which is owned by the
 * TA. It will get attested and it is kind of the "Identity" of the TA
 * instance. It is used later to sign the counter certificates. Also
 * this function is copied from the acipher example.
 */
static TEE_Result gen_key(struct ta_state *state, uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	// for more information look in the acipher example
	DMSG("has been called");
	TEE_Result res;
	uint32_t key_size;
	TEE_ObjectHandle key;
	const uint32_t key_type = TEE_TYPE_RSA_KEYPAIR;
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);

	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	key_size = RSA_KEY_SIZE_BITS;

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
	DMSG("Done!");
	return TEE_SUCCESS;
}

static TEE_Result inc_counter(struct ta_state *state, uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	DMSG("has been called");
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	state->counter.u += 1;
	DMSG("Counter: %d", state->counter.u);
	return TEE_SUCCESS;
}

/*
 * This function calculates the counter certificate. It first get the hash
 * of the recent counter value and then sign it with the attestation key
 * (AK). The complete certificate is returned to the Normal World.
 */
static TEE_Result counter_cert(struct ta_state *state, uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	DMSG("has been called");
	const uint32_t exp_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_MEMREF_OUTPUT,
						TEE_PARAM_TYPE_NONE,
						TEE_PARAM_TYPE_NONE);
	if (param_types != exp_pt)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!state->key)
		return TEE_ERROR_BAD_STATE;

	TEE_Result res;
	TEE_OperationHandle op;
	uint32_t digest_len = HASH_SIZE;
	uint8_t digest[digest_len];
	uint32_t sig_len = RSA_KEY_SIZE_BYTES;
	uint8_t sig[sig_len];

	res = create_digest(state->counter.c, sizeof(state->counter),
						digest, &digest_len);
	if (res)
		return res;

	res = TEE_AllocateOperation(&op, SIGN_ALGO,
								TEE_MODE_SIGN, RSA_KEY_SIZE_BITS);
	if (res) {
		EMSG("TEE_AllocateOperation(TEE_MODE_SIGN, %#" PRIx32 ", %" PRId32 "): %#" PRIx32,
			SIGN_ALGO, RSA_KEY_SIZE_BITS, res);
		return res;
	}

	res = TEE_SetOperationKey(op, state->key);
	if (res) {
		EMSG("TEE_SetOperationKey: %#" PRIx32, res);
		return res;
	}

	res = TEE_AsymmetricSignDigest(op, (TEE_Attribute *)NULL, 0,
								digest, digest_len, sig, &sig_len);
	if (res) {
		EMSG("TEE_AsymmetricSignDigest: %#" PRIx32, res);
		return res;
	}

	TEE_FreeOperation(op);

	params[0].memref.size = sizeof(state->counter);
	memcpy(params[0].memref.buffer, state->counter.c, sizeof(state->counter));

	params[1].memref.size = sizeof(sig);
	memcpy(params[1].memref.buffer, sig,  sizeof(sig));

	return TEE_SUCCESS;
}

/* ****************************************************************************
 * The following functions are defined in the Global Platform API and are mandatory
 * - TA_CreateEntryPoint(void)
 * - TA_DestroyEntryPoint(void)
 * - TA_OpenSessionEntryPoint(...)
 * - TA_CloseSessionEntryPoint(void *session)
 * - TA_InvokeCommandEntryPoint(...)
 */
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void){}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void **session)
{
	DMSG("has been called");
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	struct ta_state *state;

	state = TEE_Malloc(sizeof(*state), 0);
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	state->key = TEE_HANDLE_NULL;
	state->counter.u = 0;

	*session = state;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
	struct ta_state *state = session;

	TEE_FreeTransientObject(state->key);
	TEE_Free(state);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case ATTESTATION:
		return attestation(session, param_types, params);
	case GEN_NEW_KEY:
		return gen_key(session, param_types, params);
	case INCREMENT:
		return inc_counter(session, param_types, params);
	case COUNTER_CERT:
		return counter_cert(session, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
