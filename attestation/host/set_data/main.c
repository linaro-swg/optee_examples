// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Elias von Däniken
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the PTA's h-file(s)) */
#define ATTESTATION_UUID \
		{ 0xa2b0b139, 0x82dc, 0x4ffc, \
			{ 0xa8, 0xa8, 0x7d, 0x7c, 0x63, 0x66, 0xe9, 0x84 } }

#include "../common/cJSON.h"
#include "../common/base64.h"

#define NW_ERROR 1
#define NW_SUCCESS 0

/* header of the attestation data */
struct header {
	size_t iv_size;
	size_t pub_size;
	size_t enc_priv_size;
	size_t sig_size;
} h;

/* binary data, ready to be transferred to the secure world */
struct attestation_data {
	uint8_t *iv;
	uint8_t *pub;
	uint8_t *enc_priv;
	uint8_t *sig;
} d;

/*
 * Do check the input arguments.
 * 2 arguments are needed and the second has to be a file.
 * The existence of the file is also checked.
 */
int check_args(int count, char **args)
{
	FILE *file;

	if (count < 2) {
		printf("No file is provided\n");
		return NW_ERROR;
	}

	if (count > 2) {
		printf("Too many arguments\n");
		return NW_ERROR;
	}

	file = fopen(args[1], "r");
	if (file == NULL) {
		fclose(file);
		printf("File does not exist many arguments\n");
		return NW_ERROR;
	}
	return NW_SUCCESS;
}

int load_file_to_json(char *file_name, cJSON **json)
{
	unsigned long len;
	char *string;
	FILE *file;

	file = fopen(file_name, "rb");
	if (file == NULL)
		return NW_ERROR;

	fseek(file, 0, SEEK_END);
	len = (unsigned long) ftell(file);

	fseek(file, 0, SEEK_SET);
	string = (char *)malloc(len * sizeof(char));
	fread(string, len, len, file);

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
 * Parses an integer out of a json object.
 * The integer is encoded as a base64 string.
 * The fuction applies little endianness.
 */
int parse_int(const char *str, cJSON *json, size_t *size)
{
	unsigned char plain[sizeof(uint32_t)] = {};
	const cJSON *tmp = cJSON_GetObjectItemCaseSensitive(json, str);

	if (cJSON_IsString(tmp) && (tmp->valuestring != NULL)) {
		if (base64_decode(tmp->valuestring, 8, plain))
			return NW_ERROR;
	} else
		return NW_ERROR;

	 // Attention endianness (little)
	*size = (plain[0] << 24 |
				plain[1] << 16 |
				plain[2] << 8  |
				plain[3] << 0);
	return NW_SUCCESS;
}

/*
 * Parses a string out of a json object.
 * In the process memory is allocated,
 * which has to get freed later.
 */
int parse_str(const char *str, cJSON *json,
				unsigned char **data, size_t size)
{
	const cJSON *tmp = NULL;

	*data = (uint8_t *)malloc(size*sizeof(uint8_t));
	tmp = cJSON_GetObjectItemCaseSensitive(json, str);
	if (cJSON_IsString(tmp) && (tmp->valuestring != NULL)) {
		if (base64_decode(tmp->valuestring,
							plain_len_to_enc(size),
							*data))
			return NW_ERROR;
	}
	return NW_SUCCESS;
}

/*
 * Parses the header out of the json object int the global struct h.
 */
int parse_header(cJSON **json)
{
	int res;
	cJSON *header = NULL;

	header = cJSON_GetObjectItemCaseSensitive(*json, "header");
	res = parse_int("iv_size", header, &h.iv_size);
	res = parse_int("pub_size", header, &h.pub_size);
	res = parse_int("enc_priv_size", header, &h.enc_priv_size);
	res = parse_int("sig_size", header, &h.sig_size);

	if (res)
		return NW_ERROR;
	return NW_SUCCESS;
}

/*
 * Parses the data out of the json object int the global struct d.
 */
int parse_data(cJSON **json)
{
	int res;

	res = parse_str("iv", *json, &d.iv, h.iv_size);
	res = parse_str("pub", *json, &d.pub, h.pub_size);
	res = parse_str("enc_priv", *json, &d.enc_priv, h.enc_priv_size);
	res = parse_str("sig", *json, &d.sig, h.sig_size);

	if (res)
		return NW_ERROR;
	return NW_SUCCESS;
}

/*
 * Opens a connection to the attestation PTA
 * and transfers the loaded attestation data to it.
 */
int set_att_data(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = ATTESTATION_UUID;
	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT);

	op.params[0].tmpref.buffer = d.iv;
	op.params[0].tmpref.size = h.iv_size;
	op.params[1].tmpref.buffer = d.pub;
	op.params[1].tmpref.size = h.pub_size;
	op.params[2].tmpref.buffer = d.enc_priv;
	op.params[2].tmpref.size = h.enc_priv_size;
	op.params[3].tmpref.buffer = d.sig;
	op.params[3].tmpref.size = h.sig_size;

	res = TEEC_InvokeCommand(&sess, 0, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	if (res)
		return res;
	return NW_SUCCESS;
}

int main(int argc, char *argv[])
{
	cJSON *cjson = NULL;

	if (check_args(argc, argv)) {
		printf("check_args failed!\n");
		return NW_ERROR;
	}

	if (load_file_to_json(argv[1], &cjson)) {
		printf("load_file_to_json failed!\n");
		return NW_ERROR;
	}

	if (parse_header(&cjson)) {
		printf("parse_header failed!\n");
		return NW_ERROR;
	}

	if (parse_data(&cjson)) {
		printf("parse_data failed!\n");
		return NW_ERROR;
	}

	if (set_att_data()) {
		printf("set_att_data failed!\n");
		return NW_ERROR;
	}

	free(d.iv);
	free(d.pub);
	free(d.enc_priv);
	free(d.sig);
	cJSON_Delete(cjson);

	printf("Attestation Data is set!\n");
	return NW_SUCCESS;
}
