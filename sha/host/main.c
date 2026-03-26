// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <sha_ta.h>

/* Algo Type */
#define SHA_HMAC	0
#define BASE_SHA        1
#define CMAC            2

/* Maximum sizes */
#define MAX_KEY_SIZE    128
#define MAX_IV_SIZE     16

/* Algorithm information structure */
struct algo_info {
	const char *name;
	uint32_t tee_algo_id;
	enum ta_sha_object_type obj_type;
	size_t key_byte_size;
	size_t iv_size;
	bool needs_key;
	bool needs_iv;
	uint32_t algo_type;
};

/* Algorithm table */
static const struct algo_info algo_table[] = {
	/* HMAC algorithms - require key, NO IV */
	{"HMAC_SHA1",   TEE_ALG_HMAC_SHA1,   TA_SHA_OBJ_TYPE_HMAC_SHA1,   64,  0, true, false, SHA_HMAC},
	{"HMAC_SHA224", TEE_ALG_HMAC_SHA224, TA_SHA_OBJ_TYPE_HMAC_SHA224, 64,  0, true, false, SHA_HMAC},
	{"HMAC_SHA256", TEE_ALG_HMAC_SHA256, TA_SHA_OBJ_TYPE_HMAC_SHA256, 128, 0, true, false, SHA_HMAC},
	{"HMAC_SHA384", TEE_ALG_HMAC_SHA384, TA_SHA_OBJ_TYPE_HMAC_SHA384, 128, 0, true, false, SHA_HMAC},
	{"HMAC_SHA512", TEE_ALG_HMAC_SHA512, TA_SHA_OBJ_TYPE_HMAC_SHA512, 128, 0, true, false, SHA_HMAC},
	{"HMAC_SHA3_224", TEE_ALG_HMAC_SHA3_224, TA_SHA_OBJ_TYPE_HMAC_SHA3_224, 128, 0, true, false, SHA_HMAC},
	{"HMAC_SHA3_256", TEE_ALG_HMAC_SHA3_256, TA_SHA_OBJ_TYPE_HMAC_SHA3_256, 128, 0, true, false, SHA_HMAC},
	{"HMAC_SHA3_384", TEE_ALG_HMAC_SHA3_384, TA_SHA_OBJ_TYPE_HMAC_SHA3_384, 128, 0, true, false, SHA_HMAC},
	{"HMAC_SHA3_512", TEE_ALG_HMAC_SHA3_512, TA_SHA_OBJ_TYPE_HMAC_SHA3_512, 128, 0, true, false, SHA_HMAC},

	/* CMAC algorithm - requires key AND IV */
	{"AES_CMAC",    TEE_ALG_AES_CMAC,    TA_SHA_OBJ_TYPE_AES,         16,  16, true, true, CMAC},

	/* Digest algorithms - no key or IV */
	{"SHA1",        TEE_ALG_SHA1,        0,                           0,   0, false, false, BASE_SHA},
	{"SHA224",      TEE_ALG_SHA224,      0,                           0,   0, false, false, BASE_SHA},
	{"SHA256",      TEE_ALG_SHA256,      0,                           0,   0, false, false, BASE_SHA},
	{"SHA384",      TEE_ALG_SHA384,      0,                           0,   0, false, false, BASE_SHA},
	{"SHA512",      TEE_ALG_SHA512,      0,                           0,   0, false, false, BASE_SHA},
	{"SHA3_224",    TEE_ALG_SHA3_224,    0,                           0,   0, false, false, BASE_SHA},
	{"SHA3_256",    TEE_ALG_SHA3_256,    0,                           0,   0, false, false, BASE_SHA},
	{"SHA3_384",    TEE_ALG_SHA3_384,    0,                           0,   0, false, false, BASE_SHA},
	{"SHA3_512",    TEE_ALG_SHA3_512,    0,                           0,   0, false, false, BASE_SHA},
	{"SHAKE128",    TEE_ALG_SHAKE128,    0,                           0,   0, false, false, BASE_SHA},
	{"SHAKE256",    TEE_ALG_SHAKE256,    0,                           0,   0, false, false, BASE_SHA},
	{NULL, 0, 0, 0, 0, false, false, 0} /* Sentinel */
};

/* TEE resources */
struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
	uint32_t algo_num;
};

static void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_SHA_UUID;
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

static void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}

/*
 * Hex string to bytes converter
 * Converts hex string (e.g., "a5b6c7") to binary bytes
 */
static int hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t max_bytes, size_t *out_len)
{
	size_t hex_len = strlen(hex_str);
	size_t byte_len = hex_len / 2;

	if (hex_len % 2 != 0) {
		fprintf(stderr, "Error: Hex string must have even number of characters\n");
		return -1;
	}

	if (byte_len > max_bytes) {
		fprintf(stderr, "Error: Hex string too long (max %zu bytes)\n", max_bytes);
		return -1;
	}

	for (size_t i = 0; i < byte_len; i++) {
		unsigned int byte_val;
		if (!isxdigit((unsigned char)hex_str[i * 2]) ||
		    !isxdigit((unsigned char)hex_str[i * 2 + 1])) {
			fprintf(stderr, "Error: Invalid hex character at position %zu\n", i * 2);
			return -1;
		}
		sscanf(hex_str + (i * 2), "%2x", &byte_val);
		bytes[i] = (uint8_t)byte_val;
	}

	*out_len = byte_len;
	return 0;
}

/*
 * Get algorithm info by name
 */
static const struct algo_info *get_algo_info(const char *name)
{
	int i = 0;

	for (i = 0; algo_table[i].name != NULL; i++) {
		if (strcmp(algo_table[i].name, name) == 0) {
			return &algo_table[i];
		}
	}
	return NULL;
}

static int read_file_contents(const char *filepath, uint8_t **buffer, size_t *size)
{
	FILE *f = NULL;
	long file_size = 0;
	uint8_t *data = NULL;
	size_t bytes_read = 0;
	int ret = -1;

	f = fopen(filepath, "rb");
	if (!f) {
		fprintf(stderr, "Error: Cannot open file '%s'\n", filepath);
		return -1;
	}

	/* Get file size */
	if (fseek(f, 0, SEEK_END) != 0) {
		fprintf(stderr, "Error: Cannot seek to end of file '%s'\n", filepath);
		goto out;
	}

	file_size = ftell(f);
	if (file_size < 0) {
		fprintf(stderr, "Error: Cannot get file size for '%s'\n", filepath);
		goto out;
	}

	if (file_size == 0) {
		fprintf(stderr, "Error: File '%s' is empty\n", filepath);
		goto out;
	}

	rewind(f);

	/* Allocate buffer */
	data = malloc(file_size);
	if (!data) {
		fprintf(stderr, "Error: Cannot allocate memory for file '%s' (%ld bytes)\n",
			filepath, file_size);
		goto out;
	}

	/* Read file contents */
	bytes_read = fread(data, 1, file_size, f);
	if (bytes_read != (size_t)file_size) {
		fprintf(stderr, "Error: Failed to read complete file '%s' (read %zu of %ld bytes)\n",
			filepath, bytes_read, file_size);
		goto out;
	}

	*buffer = data;
	*size = (size_t)file_size;
	ret = 0;

out:
	fclose(f);
	if (ret)
		free(data);
	return ret;
}

static void print_usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options]\n\n", progname);
	fprintf(stderr, "Example of hash, HMAC and CMAC in a TA.\n\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  --algo <name>       Algorithm name (default: HMAC_SHA256)\n");
	fprintf(stderr, "                      Valid: HMAC_SHA1, HMAC_SHA224, HMAC_SHA256,\n");
	fprintf(stderr, "                             HMAC_SHA384, HMAC_SHA512,\n");
	fprintf(stderr, "                             HMAC_SHA3_224, HMAC_SHA3_256,\n");
	fprintf(stderr, "                             HMAC_SHA3_384, HMAC_SHA3_512,\n");
	fprintf(stderr, "                             AES_CMAC, SHA1, SHA224, SHA256,\n");
	fprintf(stderr, "                             SHA384, SHA512, SHA3_224, SHA3_256,\n");
	fprintf(stderr, "                             SHA3_384, SHA3_512, SHAKE128, SHAKE256\n\n");
	fprintf(stderr, "  --input <string>    Input string to process (optional, default: \"test message\")\n\n");
	fprintf(stderr, "  --input-file <path> Input file to process (optional, overrides --input)\n\n");
	fprintf(stderr, "  --key <hex_string>  Key in hexadecimal (optional, uses default if not provided)\n");
	fprintf(stderr, "                      Required for HMAC and CMAC algorithms\n\n");
	fprintf(stderr, "  --iv <hex_string>   IV in hexadecimal (optional, uses default if not provided)\n");
	fprintf(stderr, "                      Required only for AES_CMAC algorithm\n\n");
	fprintf(stderr, "  --help, -h          Display this help message\n\n");
	fprintf(stderr, "Examples:\n");
	fprintf(stderr, "  %s\n", progname);
	fprintf(stderr, "  %s --algo HMAC_SHA1\n", progname);
	fprintf(stderr, "  %s --algo HMAC_SHA256 --input \"Hello, World!\"\n", progname);
	fprintf(stderr, "  %s --algo HMAC_SHA256 --input-file test.bin\n", progname);
	fprintf(stderr, "  %s --algo SHA256 --input-file document.pdf\n", progname);
	fprintf(stderr, "  %s --algo HMAC_SHA256 --input-file firmware.bin --key a5a5a5a5...\n", progname);
	fprintf(stderr, "  %s --algo AES_CMAC --input-file data.bin --key c3c3... --iv 0000...\n\n", progname);
	fprintf(stderr, "Note: --key and --iv are optional. Default key is 0xa5 pattern,\n");
	fprintf(stderr, "      default IV is all zeros for CMAC. Default input is \"test message\".\n");
}

static void compute_digest(struct test_ctx *ctx, void *message, size_t msg_len,
		    void *digest, size_t *digest_len)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = msg_len;
	op.params[1].tmpref.buffer = digest;
	op.params[1].tmpref.size = *digest_len;
	op.params[2].value.a = ctx->algo_num;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_COMPUTE_DIGEST, &op,
				 &origin);

	*digest_len = op.params[1].tmpref.size;

	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand(COMPUTE DIGEST) failed 0x%x origin 0x%x",
		     res, origin);
	}
}

static void prepare_hmac_sha(struct test_ctx *ctx, size_t key_byte_size,
		      enum ta_sha_object_type obj_type)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = ctx->algo_num;
	op.params[1].value.a = key_byte_size;
	op.params[2].value.a = (uint32_t)obj_type;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_PREPARE,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
}

static void set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_SET_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

static void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}

static void sha_update_ops(struct test_ctx *ctx, void *message, size_t message_sz,
		    void *hmac_buff, size_t *hmac_sz)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;
	TEEC_Result res = TEEC_ERROR_GENERIC;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = message_sz;
	op.params[1].tmpref.buffer = hmac_buff;
	op.params[1].tmpref.size = *hmac_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_COMPUTE_MAC, &op,
				 &origin);

	*hmac_sz = op.params[1].tmpref.size;

	if (res != TEEC_SUCCESS) {
		errx(1, "TEEC_InvokeCommand(SHA_OPS) failed 0x%x origin 0x%x",
		     res, origin);
	}
}

static TEEC_Result compare_hmac_sha(struct test_ctx *ctx, void *message,
				    size_t message_sz, void *hmac_buff,
				    size_t *hmac_sz)
{
	TEEC_Operation op = {0};
	uint32_t origin = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = message;
	op.params[0].tmpref.size = message_sz;
	op.params[1].tmpref.buffer = hmac_buff;
	op.params[1].tmpref.size = *hmac_sz;

	return TEEC_InvokeCommand(&ctx->sess, TA_SHA_CMD_COMPARE_MAC, &op,
				  &origin);
}

int main(int argc, char *argv[])
{
	struct test_ctx ctx = {0};
	void *message = NULL;
	size_t message_sz = 0;
	char buff[64] = {0};
	size_t buff_sz = sizeof(buff);
	const struct algo_info *algo_info = NULL;
	char *algo_name = NULL;
	char *input_str = NULL;
	char *input_file = NULL;
	char *key_hex = NULL;
	char *iv_hex = NULL;
	uint8_t *file_buffer = NULL;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	int rc = 0;

	/* User-provided or default key/IV */
	uint8_t user_key[MAX_KEY_SIZE];
	size_t user_key_len = 0;
	uint8_t user_iv[MAX_IV_SIZE];
	size_t user_iv_len = 0;

	/* Parse command-line arguments */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 ||
		    strcmp(argv[i], "-h") == 0) {
			print_usage(argv[0]);
			return 0;
		} else if (strcmp(argv[i], "--algo") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "Error: --algo requires an algorithm name\n");
				print_usage(argv[0]);
				return -1;
			}
			algo_name = argv[++i];
			algo_info = get_algo_info(algo_name);
			if (!algo_info) {
				fprintf(stderr, "Error: Unknown algorithm '%s'\n", algo_name);
				print_usage(argv[0]);
				return -1;
			}
		} else if (strcmp(argv[i], "--input") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "Error: --input requires a string\n");
				print_usage(argv[0]);
				return -1;
			}
			input_str = argv[++i];
		} else if (strcmp(argv[i], "--input-file") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "Error: --input-file requires a file path\n");
				print_usage(argv[0]);
				return -1;
			}
			input_file = argv[++i];
		} else if (strcmp(argv[i], "--key") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "Error: --key requires a hexadecimal string\n");
				print_usage(argv[0]);
				return -1;
			}
			key_hex = argv[++i];
		} else if (strcmp(argv[i], "--iv") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr, "Error: --iv requires a hexadecimal string\n");
				print_usage(argv[0]);
				return -1;
			}
			iv_hex = argv[++i];
		} else {
			/*
			 * Legacy positional arguments for backward compatibility:
			 * optee_example_sha [message] [algo]
			 */
			if (!input_str) {
				input_str = argv[i];
			} else if (!algo_name) {
				algo_name = argv[i];
				algo_info = get_algo_info(algo_name);
				if (!algo_info) {
					fprintf(stderr, "Error: Unknown algorithm '%s'\n", algo_name);
					print_usage(argv[0]);
					return -1;
				}
			} else {
				fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
				print_usage(argv[0]);
				return -1;
			}
		}
	}

	/* Set defaults if not provided */
	if (!algo_info) {
		algo_info = get_algo_info("HMAC_SHA256");
		printf("Algorithm: HMAC_SHA256 (default)\n");
	} else {
		printf("Algorithm: %s (from command line)\n", algo_info->name);
	}

	/* Handle input: file takes priority over inline string, else use default */
	if (input_file) {
		if (read_file_contents(input_file, &file_buffer, &message_sz) != 0) {
			rc = -1;
			goto out;
		}
		message = file_buffer;
		printf("Using input from file: %s (%zu bytes)\n", input_file, message_sz);
	} else if (input_str) {
		message = input_str;
		message_sz = strlen(input_str);
		printf("Using input: \"%s\" (from command line)\n", input_str);
	} else {
		message = "test message";
		message_sz = strlen(message);
		printf("Using input: \"%s\" (default)\n", (char *)message);
	}

	ctx.algo_num = algo_info->tee_algo_id;

	/* Handle key and IV: command-line or defaults */
	if (key_hex || iv_hex) {
		/* Option 1: Load from command-line arguments */
		if (key_hex) {
			if (hex_to_bytes(key_hex, user_key, MAX_KEY_SIZE, &user_key_len) != 0) {
				fprintf(stderr, "Error: Invalid key hexadecimal string\n");
				rc = -1;
				goto out;
			}

			/* Validate key size */
			if (algo_info->needs_key && user_key_len != algo_info->key_byte_size) {
				fprintf(stderr, "Error: Key size mismatch. Expected %zu bytes, got %zu bytes for %s\n",
				     algo_info->key_byte_size, user_key_len, algo_info->name);
				rc = -1;
				goto out;
			}
			printf("Using key from command line (%zu bytes)\n", user_key_len);
		}

		if (iv_hex) {
			if (hex_to_bytes(iv_hex, user_iv, MAX_IV_SIZE, &user_iv_len) != 0) {
				fprintf(stderr, "Error: Invalid IV hexadecimal string\n");
				rc = -1;
				goto out;
			}

			/* Validate IV size */
			if (algo_info->needs_iv && user_iv_len != algo_info->iv_size) {
				fprintf(stderr, "Error: IV size mismatch. Expected %zu bytes, got %zu bytes for %s\n",
				     algo_info->iv_size, user_iv_len, algo_info->name);
				rc = -1;
				goto out;
			}
			printf("Using IV from command line (%zu bytes)\n", user_iv_len);
		}

		if (key_hex && !algo_info->needs_key) {
			fprintf(stderr, "Error: --key is not valid for %s\n", algo_info->name);
			rc = 1;
			goto out;
		}

		if (iv_hex && !algo_info->needs_iv) {
			fprintf(stderr, "Error: --iv is not valid for %s\n", algo_info->name);
			rc = 1;
			goto out;
		}

		/* Use defaults for missing parameters */
		if (algo_info->needs_key && !key_hex) {
			printf("Using default key (0xa5 pattern, %zu bytes)\n", algo_info->key_byte_size);
			memset(user_key, 0xa5, algo_info->key_byte_size);
			user_key_len = algo_info->key_byte_size;
		}

		if (algo_info->needs_iv && !iv_hex) {
			printf("Using default IV (0x00 pattern, %zu bytes)\n", algo_info->iv_size);
			memset(user_iv, 0x00, algo_info->iv_size);
			user_iv_len = algo_info->iv_size;
		}

	} else {
		/* Option 2: No command-line args - use defaults for algorithms that need keys */
		if (algo_info->needs_key) {
			printf("Using default key (0xa5 pattern, %zu bytes)\n", algo_info->key_byte_size);
			memset(user_key, 0xa5, algo_info->key_byte_size);
			user_key_len = algo_info->key_byte_size;
		}

		if (algo_info->needs_iv) {
			printf("Using default IV (0x00 pattern, %zu bytes)\n", algo_info->iv_size);
			memset(user_iv, 0x00, algo_info->iv_size);
			user_iv_len = algo_info->iv_size;
		}
	}

	printf("Prepare session with the TA\n");
	prepare_tee_session(&ctx);

	switch (algo_info->algo_type) {
	case BASE_SHA:
		/* Plain digest - no key or IV needed */
		printf("Compute digest\n");
		compute_digest(&ctx, message, message_sz, (void *)buff, &buff_sz);
		printf("Digest: ");
		break;

	case SHA_HMAC:
		/* HMAC - needs key, NO IV */
		printf("Prepare HMAC compute operation\n");
		prepare_hmac_sha(&ctx, algo_info->key_byte_size, algo_info->obj_type);

		printf("Load key in TA\n");
		set_key(&ctx, (char *)user_key, user_key_len);

		printf("Reset operation in TA (HMAC does not use IV)\n");
		set_iv(&ctx, NULL, 0);

		printf("Compute MAC operation\n");
		sha_update_ops(&ctx, message, message_sz, (void *)buff, &buff_sz);

		printf("Prepare HMAC compare operation\n");
		prepare_hmac_sha(&ctx, algo_info->key_byte_size, algo_info->obj_type);

		printf("Load key in TA\n");
		set_key(&ctx, (char *)user_key, user_key_len);

		printf("Reset operation in TA (HMAC does not use IV)\n");
		set_iv(&ctx, NULL, 0);

		printf("Compare the MAC\n");
		res = compare_hmac_sha(&ctx, message, message_sz,
				       (void *)buff, &buff_sz);

		if (res == TEEC_SUCCESS)
			printf("MAC successfully matching\n");
		else
			printf("MAC did not match\n");

		printf("HMAC: ");
		break;

	case CMAC:
		/* CMAC - needs both key AND IV */
		printf("Prepare CMAC compute operation\n");
		prepare_hmac_sha(&ctx, algo_info->key_byte_size, algo_info->obj_type);

		printf("Load key in TA\n");
		set_key(&ctx, (char *)user_key, user_key_len);

		printf("Reset operation in TA (provides the initial vector)\n");
		set_iv(&ctx, (char *)user_iv, user_iv_len);

		printf("Compute MAC operation\n");
		sha_update_ops(&ctx, message, message_sz, (void *)buff, &buff_sz);

		printf("Prepare CMAC compare operation\n");
		prepare_hmac_sha(&ctx, algo_info->key_byte_size, algo_info->obj_type);

		printf("Load key in TA\n");
		set_key(&ctx, (char *)user_key, user_key_len);

		printf("Reset operation in TA (provides the initial vector)\n");
		set_iv(&ctx, (char *)user_iv, user_iv_len);

		printf("Compare the MAC\n");
		res = compare_hmac_sha(&ctx, message, message_sz,
				       (void *)buff, &buff_sz);

		if (res == TEEC_SUCCESS)
			printf("MAC successfully matching\n");
		else
			printf("MAC did not match\n");

		printf("CMAC: ");
		break;

	default:
		break;
	}

	for (int32_t i = 0 ; i < buff_sz ; i++)
		printf("%02x", buff[i]);

	printf("\n");

	terminate_tee_session(&ctx);

out:
	free(file_buffer);
	return rc;
}
