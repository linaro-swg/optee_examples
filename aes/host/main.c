// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 */

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <aes_ta.h>

/* Function to read file contents */
static int read_file_contents(const char *filepath, uint8_t **buffer, size_t *size)
{
	FILE *f = NULL;
	long file_size = 0;
	uint8_t *data = NULL;
	size_t bytes_read = 0;

	f = fopen(filepath, "rb");
	if (!f) {
		fprintf(stderr, "Error: Cannot open file '%s'\n", filepath);
		return -1;
	}

	/* Get file size */
	if (fseek(f, 0, SEEK_END) != 0) {
		fprintf(stderr, "Error: Cannot seek to end of file '%s'\n", filepath);
		fclose(f);
		return -1;
	}

	file_size = ftell(f);
	if (file_size < 0) {
		fprintf(stderr, "Error: Cannot get file size for '%s'\n", filepath);
		fclose(f);
		return -1;
	}

	if (file_size == 0) {
		fprintf(stderr, "Error: File '%s' is empty\n", filepath);
		fclose(f);
		return -1;
	}

	if (fseek(f, 0, SEEK_SET) != 0) {
		fprintf(stderr, "Error: Cannot rewind file '%s'\n", filepath);
		fclose(f);
		return -1;
	}

	/* Allocate buffer */
	data = malloc(file_size);
	if (!data) {
		fprintf(stderr, "Error: Cannot allocate memory for file '%s' (%ld bytes)\n",
			filepath, file_size);
		fclose(f);
		return -1;
	}

	/* Read file contents */
	bytes_read = fread(data, 1, file_size, f);
	if (bytes_read != (size_t)file_size) {
		fprintf(stderr, "Error: Failed to read complete file '%s' (read %zu of %ld bytes)\n",
			filepath, bytes_read, file_size);
		free(data);
		fclose(f);
		return -1;
	}

	fclose(f);

	*buffer = data;
	*size = (size_t)file_size;
	return 0;
}

/* Helper function to convert hex string to bytes */
static int hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t max_len)
{
	size_t len = strlen(hex_str);
	size_t byte_len = 0;
	size_t i = 0;

	if (len % 2 != 0) {
		fprintf(stderr, "Error: Hex string must have even length\n");
		return -1;
	}

	byte_len = len / 2;

	if (byte_len > max_len) {
		fprintf(stderr, "Error: Hex string too long (max %zu bytes)\n",
			max_len);
		return -1;
	}

	for (i = 0; i < byte_len; i++) {
		if (sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]) != 1) {
			fprintf(stderr,
				"Error: Invalid hex character at position %zu\n",
				2 * i);
			return -1;
		}
	}

	return (int)byte_len;
}

#define AES_TEST_BUFFER_SIZE	4096
#define AES_TEST_KEY_SIZE	16
#define AES_BLOCK_SIZE		16

#define DECODE			0
#define ENCODE			1

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint32_t algo_num;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_AES_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

void prepare_aes(struct test_ctx *ctx, int encode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = ctx->algo_num;
	op.params[1].value.a = TA_AES_SIZE_128BIT;
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE :
					TA_AES_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
}

void set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);

	if (ctx->algo_num == TA_AES_ALGO_ECB) {
		iv = NULL;
		iv_sz = 0;
	}

	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}

void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			res, origin);
}

void auth_enc_op(struct test_ctx *ctx, uint32_t encrypt, void *in_buf, size_t
		  in_sz, void *out_buf, size_t *out_sz, void *tag, size_t
		  *tag_len)
{
	TEEC_Operation op;
	TEEC_Result res;
	uint32_t err_origin;

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INOUT);
	op.params[0].tmpref.buffer = in_buf;
	op.params[0].tmpref.size = in_sz;

	op.params[1].tmpref.buffer = out_buf;
	op.params[1].tmpref.size = *out_sz;

	op.params[2].value.a = encrypt;

	op.params[3].tmpref.buffer = tag;
	op.params[3].tmpref.size = *tag_len;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_AUTHENC,
				 &op, &err_origin);

	if (res == TEEC_SUCCESS) {
		*out_sz = op.params[1].tmpref.size;
		*tag_len = op.params[3].tmpref.size;
	} else {
		errx(1, "InvokeCommand failed with %x\n", res);
	}
}

static void print_usage(const char *progname)
{
	printf("Usage: %s [options]\n\n", progname);
	printf("Options:\n");
	printf("  --algo <algorithm>   AES algorithm (default: TA_AES_ALGO_CTR)\n");
	printf("                       Valid: TA_AES_ALGO_ECB, TA_AES_ALGO_CBC,\n");
	printf("                              TA_AES_ALGO_CTR, TA_AES_ALGO_CCM,\n");
	printf("                              TA_AES_ALGO_GCM\n\n");
	printf("  --input-file <path>  Input file to encrypt (optional)\n\n");
	printf("  --key <hex_string>   Key in hexadecimal (optional, uses default if not provided)\n");
	printf("                       16 bytes = 32 hex characters\n\n");
	printf("  --iv <hex_string>    IV/Nonce in hexadecimal (optional, uses default if not provided)\n");
	printf("                       16 bytes for CBC/CTR/ECB, 12 bytes for CCM/GCM\n\n");
	printf("  --help, -h           Show this help message\n\n");
	printf("Examples:\n");
	printf("  %s\n", progname);
	printf("  %s --algo TA_AES_ALGO_CBC\n", progname);
	printf("  %s --algo TA_AES_ALGO_GCM --input-file document.pdf\n", progname);
	printf("  %s --algo TA_AES_ALGO_CTR --key a5a5... --iv 0000...\n", progname);
	printf("  %s --input-file firmware.bin --key c3c3... --iv 1234...\n\n", progname);
	printf("Note: --key and --iv are optional. Default key is 0xa5 pattern,\n");
	printf("      default IV is all zeros. If no --input-file is provided,\n");
	printf("      a default test pattern (0x5a, %d bytes) will be used.\n", AES_TEST_BUFFER_SIZE);
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx;
	char key[AES_TEST_KEY_SIZE];
	char iv[AES_BLOCK_SIZE];
	static char clear[AES_TEST_BUFFER_SIZE];
	char *algo = NULL;
	char *input_file = NULL;
	char *key_hex = NULL;
	char *iv_hex = NULL;
	uint8_t *file_buffer = NULL;
	uint8_t *ciph = NULL;
	uint8_t *temp = NULL;
	uint8_t *ciphertext = NULL;
	uint8_t *decrypted = NULL;
	size_t ct_len = 0;
	size_t dec_len = 0;
	uint8_t tag[16] = {0};
	size_t tag_len = 16;
	size_t input_len = AES_TEST_BUFFER_SIZE;
	size_t original_len = 0;
	size_t iv_len = 0;
	int i;

	/* Parse command line arguments */
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--algo") == 0 && i + 1 < argc) {
			algo = argv[++i];
		} else if (strcmp(argv[i], "--input-file") == 0 && i + 1 < argc) {
			input_file = argv[++i];
		} else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
			key_hex = argv[++i];
		} else if (strcmp(argv[i], "--iv") == 0 && i + 1 < argc) {
			iv_hex = argv[++i];
		} else if (strcmp(argv[i], "--help") == 0 ||
			   strcmp(argv[i], "-h") == 0) {
			print_usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "Error: Unknown or incomplete option '%s'\n", argv[i]);
			fprintf(stderr, "Use --help for usage information.\n");
			return -1;
		}
	}

	/* Select algorithm */
	if (algo) {
		if (strcmp(algo, "TA_AES_ALGO_ECB") == 0) {
			ctx.algo_num = TA_AES_ALGO_ECB;
			printf("Algorithm: TA_AES_ALGO_ECB (from command line)\n");
		} else if (strcmp(algo, "TA_AES_ALGO_CBC") == 0) {
			ctx.algo_num = TA_AES_ALGO_CBC;
			printf("Algorithm: TA_AES_ALGO_CBC (from command line)\n");
		} else if (strcmp(algo, "TA_AES_ALGO_CTR") == 0) {
			ctx.algo_num = TA_AES_ALGO_CTR;
			printf("Algorithm: TA_AES_ALGO_CTR (from command line)\n");
		} else if (strcmp(algo, "TA_AES_ALGO_CCM") == 0) {
			ctx.algo_num = TA_AES_ALGO_CCM;
			printf("Algorithm: TA_AES_ALGO_CCM (from command line)\n");
		} else if (strcmp(algo, "TA_AES_ALGO_GCM") == 0) {
			ctx.algo_num = TA_AES_ALGO_GCM;
			printf("Algorithm: TA_AES_ALGO_GCM (from command line)\n");
		} else {
			fprintf(stderr, "Error: Invalid algorithm '%s'\n",
				algo);
			fprintf(stderr,
				"Valid algorithms: TA_AES_ALGO_ECB, TA_AES_ALGO_CBC, TA_AES_ALGO_CTR, TA_AES_ALGO_CCM, TA_AES_ALGO_GCM\n");
			return -1;
		}
	} else {
		ctx.algo_num = TA_AES_ALGO_CTR;
		printf("Algorithm: TA_AES_ALGO_CTR (default)\n");
	}

	/* Initialize key - use default, then override if provided */
	memset(key, 0xa5, AES_TEST_KEY_SIZE);
	if (key_hex) {
		int ret = hex_to_bytes(key_hex, (uint8_t *)key, AES_TEST_KEY_SIZE);

		if (ret < 0 || ret != AES_TEST_KEY_SIZE) {
			if (ret >= 0)
				fprintf(stderr, "Error: KEY must be 16 bytes (32 hex chars), got %d bytes\n", ret);
			return -1;
		}
		printf("Using key from: command line\n");
	} else {
		printf("Using key from: default (0xa5 repeated)\n");
	}

	/* Initialize IV - use default, then override if provided */
	if (ctx.algo_num == TA_AES_ALGO_CCM || ctx.algo_num == TA_AES_ALGO_GCM) {
		memset(iv, 0, 12);
		iv_len = 12;
	} else {
		memset(iv, 0, AES_BLOCK_SIZE);
		iv_len = AES_BLOCK_SIZE;
	}

	if (iv_hex) {
		int expected_iv_len = (ctx.algo_num == TA_AES_ALGO_CCM || ctx.algo_num == TA_AES_ALGO_GCM) ? 12 : AES_BLOCK_SIZE;
		int ret = hex_to_bytes(iv_hex, (uint8_t *)iv, expected_iv_len);

		if (ret < 0 || ret != expected_iv_len) {
			if (ret >= 0)
				fprintf(stderr, "Error: IV must be %d bytes (%d hex chars), got %d bytes\n",
					expected_iv_len, expected_iv_len * 2, ret);
			return -1;
		}
		iv_len = expected_iv_len;
		printf("Using IV from: command line\n");
	} else {
		printf("Using IV from: default (zeros)\n");
	}

	/* Handle input data */
	if (input_file) {
		/* Read from file */
		if (read_file_contents(input_file, &file_buffer, &input_len) != 0) {
			return -1;
		}
		original_len = input_len;
		printf("Using data from: file (%s, %zu bytes)\n", input_file, input_len);
	} else {
		/* Use default pattern - point file_buffer to stack clear */
		memset(clear, 0x5a, AES_TEST_BUFFER_SIZE);
		input_len = AES_TEST_BUFFER_SIZE;
		original_len = input_len;
		file_buffer = (uint8_t *)clear;
		printf("Using data from: default (0x5a repeated, %zu bytes)\n", input_len);
	}

	/* Allocate output buffers based on input size */
	if ((ctx.algo_num == TA_AES_ALGO_CCM) ||
	    (ctx.algo_num == TA_AES_ALGO_GCM)) {
		/* For AE modes - add one block size for alignment overhead */
		ct_len = input_len + AES_BLOCK_SIZE;
		ciphertext = malloc(ct_len);
		if (!ciphertext) {
			fprintf(stderr, "Error: Cannot allocate ciphertext buffer\n");
			if (file_buffer != (uint8_t *)clear)
				free(file_buffer);
			return -1;
		}
		dec_len = input_len + AES_BLOCK_SIZE;
		decrypted = malloc(dec_len);
		if (!decrypted) {
			fprintf(stderr, "Error: Cannot allocate decrypted buffer\n");
			free(ciphertext);
			if (file_buffer != (uint8_t *)clear)
				free(file_buffer);
			return -1;
		}
	} else {
		/* For traditional modes - pad to block size */
		size_t padded_len = input_len;

		if (input_len % AES_BLOCK_SIZE != 0) {
			padded_len = ((input_len + AES_BLOCK_SIZE - 1) /
				      AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
		}

		ciph = malloc(padded_len);
		if (!ciph) {
			fprintf(stderr, "Error: Cannot allocate cipher buffer\n");
			if (file_buffer != (uint8_t *)clear)
				free(file_buffer);
			return -1;
		}

		temp = malloc(padded_len);
		if (!temp) {
			fprintf(stderr, "Error: Cannot allocate temp buffer\n");
			free(ciph);
			if (file_buffer != (uint8_t *)clear)
				free(file_buffer);
			return -1;
		}

		/* If padding needed, create a padded copy */
		if (padded_len > input_len) {
			uint8_t *padded_buffer = malloc(padded_len);

			if (!padded_buffer) {
				fprintf(stderr, "Error: Cannot allocate padded buffer\n");
				free(ciph);
				free(temp);
				if (file_buffer != (uint8_t *)clear)
					free(file_buffer);
				return -1;
			}
			memcpy(padded_buffer, file_buffer, input_len);
			memset(padded_buffer + input_len, 0, padded_len - input_len);
			/* Only free file_buffer if it was dynamically allocated */
			if (file_buffer != (uint8_t *)clear)
				free(file_buffer);
			file_buffer = padded_buffer;
			input_len = padded_len;
		}
	}
	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	printf("Prepare encode operation\n");
	prepare_aes(&ctx, ENCODE);

	printf("Load key in TA\n");
	set_key(&ctx, key, AES_TEST_KEY_SIZE);

	if ((ctx.algo_num == TA_AES_ALGO_CCM) ||
	    (ctx.algo_num == TA_AES_ALGO_GCM)) {
		/* For AE modes - set nonce via set_iv */
		printf("Set nonce for AE mode (%zu bytes)\n", iv_len);
		set_iv(&ctx, iv, iv_len);

		printf("AE encode operation in TA\n");
		auth_enc_op(&ctx, TA_AES_MODE_ENCODE, file_buffer, input_len,
			    ciphertext, &ct_len, tag, &tag_len);
	} else {
		/* For traditional modes (CBC/CTR/ECB) */
		printf("Reset ciphering operation in TA (provides the initial vector)\n");
		set_iv(&ctx, iv, iv_len);

		printf("Encode buffer from TA\n");
		cipher_buffer(&ctx, (char *)file_buffer, (char *)ciph, input_len);
	}

	printf("Prepare decode operation\n");
	prepare_aes(&ctx, DECODE);

	printf("Load key in TA\n");
	set_key(&ctx, key, AES_TEST_KEY_SIZE);

	if ((ctx.algo_num == TA_AES_ALGO_CCM) ||
	    (ctx.algo_num == TA_AES_ALGO_GCM)) {
		/* Reload nonce for decode */
		printf("Set nonce for AE mode (%zu bytes)\n", iv_len);
		set_iv(&ctx, iv, iv_len);

		printf("AE decode operation in TA\n");
		auth_enc_op(&ctx, TA_AES_MODE_DECODE, ciphertext, ct_len,
			    decrypted, &dec_len, tag, &tag_len);
	} else {
		/* Reload IV for decode */
		printf("Reset ciphering operation in TA (provides the initial vector)\n");
		set_iv(&ctx, iv, iv_len);

		printf("Decode buffer from TA\n");
		cipher_buffer(&ctx, (char *)ciph, (char *)temp, input_len);
	}

	/* Check decoded is the clear content */
	if ((ctx.algo_num == TA_AES_ALGO_CCM) ||
	    (ctx.algo_num == TA_AES_ALGO_GCM)) {
		if (memcmp(file_buffer, decrypted, original_len) == 0)
			printf("CCM/GCM encryption/decryption successful!\n");
		else
			printf("Decrypted plaintext mismatch — unexpected internal error\n");
	} else {
		if (memcmp(file_buffer, temp, original_len))
			printf("Clear text and decoded text differ => ERROR\n");
		else
			printf("Clear text and decoded text match\n");
	}

	terminate_tee_session(&ctx);

	/* Clean up allocated buffers */
	if (file_buffer != (uint8_t *)clear)
		free(file_buffer);

	free(ciphertext);
	free(decrypted);
	free(ciph);
	free(temp);

	return 0;
}
