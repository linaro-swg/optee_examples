// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Elias von Däniken
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <websock.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <sample_attestation_ta.h>

#include "../common/cJSON.h"
#include "../common/base64.h"

#define NW_ERROR 1
#define NW_SUCCESS 0

#define SIZE_AK 300
#define HASH_SIZE 32
#define RSA_KEY_SIZE_BITS 2048
#define RSA_KEY_SIZE_BYTES (RSA_KEY_SIZE_BITS / 8)
#define ATT_CERT_SIZE (4 * HASH_SIZE + RSA_KEY_SIZE_BYTES)

#define ATT_DATA "/root/cert-b64.json"

#define CNTR_CERT_VALUE_LEN 4
#define CNTR_CERT_SIG_LEN 256

#define WS_COMMAND_GET_ATTESTATION_CERTIFICATE 1
#define WS_COMMAND_RESP_SUCCESSFUL_ATTESTATION 3
#define WS_COMMAND_INCREMENT_COUNTER 10
#define WS_COMMAND_GET_COUNTER_CERTIFICATE 20

FILE *file; // file which contains the attestation data

TEEC_Context ctx;
TEEC_Session sess;
TEEC_UUID uuid = TA_SAMPLE_ATTESTATION_UUID;
uint32_t err_origin;

/*
 * Convert a plain byte string into a base64 encoded json object
 * and append it to the given json object.
 */
int plain_to_json(cJSON **json, const char *name, uint8_t *data, size_t len)
{
	size_t enc_len = plain_len_to_enc(len);
	char *enc = malloc(enc_len+1);

	if (enc == NULL)
		return NW_ERROR;

	enc[enc_len] = '\0';

	if (base64_encode(data, len, enc))
		return NW_ERROR;

	cJSON_AddStringToObject(*json, name, enc);
	free(enc);
	return NW_SUCCESS;
}

/*
 * Call the sample TA to get the counter certificate
 */
int call_for_cntr_cert(uint8_t *value, uint8_t *sig)
{
	TEEC_Result res;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = value;
	op.params[0].tmpref.size = CNTR_CERT_VALUE_LEN;
	op.params[1].tmpref.buffer = sig;
	op.params[1].tmpref.size = CNTR_CERT_SIG_LEN;

	res = TEEC_InvokeCommand(&sess, COUNTER_CERT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	return NW_SUCCESS;
}

/*
 * Build the counter certificate as a json object from plain data
 */
int cntr_cert_to_json(cJSON **json, uint8_t *value, uint8_t *sig)
{
	if (plain_to_json(json, "Value", value, CNTR_CERT_VALUE_LEN))
		return NW_ERROR;

	if (plain_to_json(json, "Signature", sig, CNTR_CERT_SIG_LEN))
		return NW_ERROR;

	return NW_SUCCESS;
}

/*
 * Construct the message (id + counter_cert)
 */
int json_to_cntr_msg(cJSON **msg, cJSON **jcert)
{
	cJSON *id;

	id = cJSON_CreateNumber(21);
	if (id == NULL)
		return NW_ERROR;

	cJSON_AddItemToObject(*msg, "id", id);
	cJSON_AddItemToObject(*msg, "Counter", *jcert);
	return NW_SUCCESS;
}

/*
 * Build the attestation certificate as a json object
 * and labels every field correctly
 */
int att_cert_to_json(cJSON **att_cert,
					uint8_t *usr, size_t usr_len,
					uint8_t *ak, size_t ak_len,
					uint8_t *cert, size_t cert_len)
{

	if (plain_to_json(att_cert, "Attestation Key", ak, ak_len))
		return NW_ERROR;

	if (plain_to_json(att_cert, "User Data", usr, usr_len))
		return NW_ERROR;

	if (plain_to_json(att_cert, "Attestation Key Hash", cert + 0 * HASH_SIZE, HASH_SIZE))
		return NW_ERROR;

	if (plain_to_json(att_cert, "TA Hash", cert + 1 * HASH_SIZE, HASH_SIZE))
		return NW_ERROR;

	if (plain_to_json(att_cert, "System Measurement", cert + 2 * HASH_SIZE, HASH_SIZE))
		return NW_ERROR;

	if (plain_to_json(att_cert, "User Data Hash", cert + 3 * HASH_SIZE, HASH_SIZE))
		return NW_ERROR;

	if (plain_to_json(att_cert, "Signature", cert + 4 * HASH_SIZE, cert_len - 4 * HASH_SIZE))
		return NW_ERROR;

	return NW_SUCCESS;
}

int load_file_to_json(char *file_name, cJSON **json)
{
	unsigned long len;
	char *string;

	file = fopen(file_name, "rb");
	if (file == NULL)
		return NW_ERROR;

	// determine the length of the file
	fseek(file, 0, SEEK_END);
	len = (unsigned long)ftell(file);
	fseek(file, 0, SEEK_SET);

	// allocate the a string in the same length
	string = (char *) malloc(len * sizeof(char));
	fread(string, len, len, file);

	// parse the loaded string to an Object
	*json = cJSON_Parse(string);
	if (json == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();

		if (error_ptr != NULL)
			fprintf(stderr, "Error before: %s\n", error_ptr);
		printf("Fail: json == NULL\n");
		return NW_ERROR;
	}
	free(string);
	return NW_SUCCESS;
}

/*
 * Construct the message from different json objects
 * (id + att_data + att_cert)
 */
int json_to_att_msg(cJSON **msg, int id, cJSON **att_data, cJSON **att_cert)
{
	cJSON *jid;
	int res;

	jid = cJSON_CreateNumber(id);
	if (jid == NULL)
		return NW_ERROR;

	res = cJSON_AddItemToObject(*msg, "id", jid);
	res = cJSON_AddItemToObject(*msg, "data", *att_data);
	res = cJSON_AddItemToObject(*msg, "cert", *att_cert);
	if (!res)
		return NW_ERROR;
	return NW_SUCCESS;
}


/*
 * Convert the plain data from the call to the sample TA
 * into the message for the validater
 */
int att_cert_to_msg(cJSON **msg,
					uint8_t *usr, size_t usr_len,
					uint8_t *ak, size_t ak_len,
					uint8_t *cert, size_t cert_len)
{
	cJSON *att_data, *att_cert;

	att_cert = cJSON_CreateObject();
	if (att_cert == NULL)
		return NW_ERROR;

	if (att_cert_to_json(&att_cert, usr, usr_len, ak, ak_len, cert, cert_len))
		return NW_ERROR;

	att_data = cJSON_CreateObject();
	if (att_data == NULL)
		return NW_ERROR;

	if (load_file_to_json(ATT_DATA, &att_data))
		return NW_ERROR;

	if (json_to_att_msg(msg, 2, &att_data, &att_cert))
		return NW_ERROR;

	return NW_SUCCESS;
}

/*
 * Call the TA for an attestation certificate
 */
int call_for_att_cert(uint8_t *usr_data, size_t *usr_data_len,
					 uint8_t *ak,  size_t *ak_len,
					 uint8_t *cert,  size_t *cert_len)
{
	TEEC_Result res;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = usr_data;
	op.params[0].tmpref.size = *usr_data_len;
	op.params[1].tmpref.buffer = ak;
	op.params[1].tmpref.size = SIZE_AK;
	op.params[2].tmpref.buffer = cert;
	op.params[2].tmpref.size = ATT_CERT_SIZE;


	res = TEEC_InvokeCommand(&sess, ATTESTATION, &op,
				 &err_origin);
	if (res)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	*ak_len = op.params[1].tmpref.size;
	*cert_len = op.params[2].tmpref.size;
	return NW_SUCCESS;
}


// ****************************************************************************
// ----------------------------- Commands of the TA ---------------------------
// ****************************************************************************

/*
 * Call the sample TA to request a new keypair.
 * The keypair kept inside the TA.
 */
int gen_key(void)
{
	TEEC_Result res;
	TEEC_Operation op;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, GEN_NEW_KEY, &op,
				 &err_origin);
	if (res) {
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
		return NW_ERROR;
	}
	return NW_SUCCESS;
}

/*
 * Call the sample TA to request the attestation certificate.
 * Convert it then into a base64 encoded json object
 * which is sent back to the validater.
 */
int attestation(libwebsock_client_state *state,
				uint8_t *usr_data, size_t usr_data_len)
{
	cJSON *msg;
	uint8_t ak_pub[SIZE_AK];
	uint8_t att_cert[ATT_CERT_SIZE];
	size_t ak_pub_len, att_cert_len;

	if (call_for_att_cert(usr_data, &usr_data_len,
					 ak_pub, &ak_pub_len,
					 att_cert, &att_cert_len))
		return NW_ERROR;

	msg = cJSON_CreateObject();
	if (msg == NULL)
		return NW_ERROR;

	if (att_cert_to_msg(&msg, usr_data, usr_data_len,
					 ak_pub, ak_pub_len,
					 att_cert, att_cert_len))
		return NW_ERROR;

	libwebsock_send_text(state, cJSON_Print(msg));

	return NW_SUCCESS;
}

/*
 * Call the sample TA to increase the secure counter inside the TA.
 */
int inc(void)
{
	TEEC_Result res;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, INCREMENT, &op,
				 &err_origin);
	if (res)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	return NW_SUCCESS;
}

/*
 *  Call the sample TA for the counter certificate.
 *  Convert the binary data to base64 and pack it in JSON object,
 *  which is sent back to the validater.
 */
int ctr_cert(libwebsock_client_state *state)
{
	uint8_t value[CNTR_CERT_VALUE_LEN];
	uint8_t sig[CNTR_CERT_SIG_LEN];
	cJSON *jcert;
	cJSON *msg;

	if (call_for_cntr_cert(value, sig))
		return NW_ERROR;

	jcert = cJSON_CreateObject();
	if (cntr_cert_to_json(&jcert, value, sig))
		return NW_ERROR;

	msg = cJSON_CreateObject();
	if (json_to_cntr_msg(&msg, &jcert))
		return NW_ERROR;

	libwebsock_send_text(state, cJSON_Print(msg));

	cJSON_Delete(msg);
	return NW_SUCCESS;
}

// ****************************************************************************
// --------------------------------  websocket  -------------------------------
// ****************************************************************************

int onmessage(libwebsock_client_state *state, libwebsock_message *msg)
{
	static bool att;

	printf("\nReceived message from client: %d\n", state->sockfd);
	printf("Message opcode: %d\n", msg->opcode);
	printf("Payload Length: %llu\n", msg->payload_len);
	printf("Payload: %s\n", msg->payload);

	//parse the payload into an JSON Object
	cJSON *json = cJSON_Parse(msg->payload);

	if (json == NULL) {
		const char *error_ptr = cJSON_GetErrorPtr();

		if (error_ptr != NULL)
			fprintf(stderr, "Error before: %s\n", error_ptr);
		printf("Fail: json == NULL\n");
		exit(1);
	}

	// extract the message id
	uint8_t id = 0;
	const cJSON *tmp = NULL;

	tmp = cJSON_GetObjectItemCaseSensitive(json, "id");
	if (cJSON_IsNumber(tmp) && (tmp->valueint != 0)) {
		id = tmp->valueint;
	} else {
		printf("tmp->valueint failed\n");
		exit(1);
	}

	// do the things requested in the message
	printf("id: %d\n", id);
	switch (id) {

	// get a new attestation certificate
	case WS_COMMAND_GET_ATTESTATION_CERTIFICATE:

		// generate a new key inside the ta
		if (gen_key()) {
			printf("AK key generation failed!\n");
			exit(1);
		}

		// extract the random number for the challenge (aka user data)
		unsigned char plain[HASH_SIZE] = {};
		const cJSON *tmp = NULL;

		tmp = cJSON_GetObjectItemCaseSensitive(json, "rn");
		if (cJSON_IsString(tmp) && (tmp->valuestring != NULL)) {
			printf("rn : %s\n", tmp->valuestring);
			if (base64_decode(tmp->valuestring,
								plain_len_to_enc(sizeof(plain)),
								plain)) {
				printf("decoding rn failed!");
				exit(1);
			}
		} else {
			printf("extract tmp->valuestring failed\n");
			exit(1);
		}

		// call the TA for the Attestation cert and send it back
		printf("call for attestation certificate\n");
		if (attestation(state, plain, 32)) {
			printf("attestation call failed!\n");
			exit(1);
		}
		break;

	// reply for a successful attestation
	case WS_COMMAND_RESP_SUCCESSFUL_ATTESTATION:
		if (att) {
			printf("Device was already attestated!\n");
			exit(1);
		}
		att = true;
		printf("Attestation Certificate was accepted!\n");
		break;


	// incrementing counter
	case WS_COMMAND_INCREMENT_COUNTER:
		if (!att) {
			printf("Device is not attestated!\n");
			exit(1);
		}

		printf("Incrementing counter!\n");
		inc();

		// report job done
		libwebsock_send_text(state, "{\"id\": 11}");
		break;

	// counter certificate request
	case WS_COMMAND_GET_COUNTER_CERTIFICATE:
		if (!att) {
			printf("Device is not attestated!\n");
			exit(1);
		}

		printf("Counter Certificate was requested!\n");
		if (ctr_cert(state))
			printf("Request failed!\n");
		break;
	default:
		break;
	}

	return NW_SUCCESS;
}

int onopen(libwebsock_client_state *state)
{
	printf("%s socketfd:  %d\n", __func__, state->sockfd);
	TEEC_Result res;

	// check if already a connection exists
	if (ctx.fd != 0) {
		printf("check failed\n");
		libwebsock_close(state);
		return NW_ERROR;
	}

	// initialize a context connecting us to the TEE
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	return NW_SUCCESS;
}

int onclose(libwebsock_client_state *state)
{
	printf("%s: %d\n", __func__, state->sockfd);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return NW_SUCCESS;
}

int main(void)
{
	libwebsock_context *ctx = NULL;
	char port[] = "16800";

	ctx = libwebsock_init();
	if (ctx == NULL) {
		fprintf(stderr, "Error during libwebsock_init.\n");
		exit(1);
	}

	libwebsock_bind(ctx, "0.0.0.0", port);
	printf("libwebsock listening on port %s\n", port);
	ctx->onmessage = onmessage;
	ctx->onopen = onopen;
	ctx->onclose = onclose;
	libwebsock_wait(ctx);

	return NW_SUCCESS;
}
