/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

/*
 * This application demonstrates the zero-copy (no intermediate buffer) data
 * exchange between Client Application (CA) and User Trusted Application (UTA).
 *
 * It relies on message queue service for synchronization between data
 * writes/reads. An API already exists to register shared memory between CA and
 * TA.
 *
 * Anonymous mmap() is used for getting the Normal World memory, which could be
 * replaced with device memory.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>

#include <tee_client_api.h>
#include <zero_copy_ta.h>
#include <ree_service_api.h>

/*
 * struct zero_copy
 * @service  : Handle to the REE service
 */
struct zero_copy {
	void *msgq_hdl;
	void *buf;
	size_t size;
} zcopy;

/* TODO: Write signal handler make the thread exit */

/**
 * msgq_zcopy_service() - Fill the shared buffer
 */
void *msgq_zcopy_service(void *arg)
{
	int ret;
	size_t num_params;
	struct tee_params params[4] = {0};
	static int count = 0;

	/* Process the message */
	do {
		/* Wait for the message */
		ret = ree_service_rcv(zcopy.msgq_hdl, &num_params, params);
		if (ret) {
			printf("Failed to receive msg\n");
			goto err;
		}

		/* TODO: Check for the parameter count */
		switch(params[0].u.value.a) {
		case REE_ZERO_COPY_FILL_BUFFER:
		{
			char str[64];
			printf("TEE->REE: %s\n", (char *)zcopy.buf);
			snprintf(str, sizeof(str), "Hello! from REE %d", count++);
			strncpy(zcopy.buf, str, zcopy.size);
			break;
		}

		/* Init/Shutdown the service */
		case OPTEE_MRC_REE_SERVICE_START:
		case OPTEE_MRC_REE_SERVICE_STOP:
			break;

		default:
			printf("msgq: Unknown command received: %lu\n",
							params[0].u.value.a);
			break;
		}

		/* Send the response */
		ret = ree_service_snd(zcopy.msgq_hdl, num_params, params, 0);
		if (ret) {
			printf("Failed to send status \n");
			goto err;
		}

	} while (1);

err:
	return NULL;
}

int main(int argc, char *argv[])
{
	int ret;
	size_t mem_size = 4 * 1024;
	pthread_t msgq_thread;
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op = {0};
	TEEC_SharedMemory shared_mem_desc = {0};
	TEEC_UUID ta_uuid = TA_ZERO_COPY_UUID;
	TEEC_UUID msgq_uuid = REE_ZERO_COPY_MSGQ_UUID;
	uint32_t err_origin;

	/* Setup Zero Copy structure. This mmap could be of device memory too */
	zcopy.buf = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!zcopy.buf)
		errx(1, "Failed to map 4k shared memory");
	zcopy.size = mem_size;

	/* Start the Zero Copy Message Queue Service */
	ret = ree_service_init(&msgq_uuid, &zcopy.msgq_hdl);
	if (ret)
		errx(1, "Failed to register Zero Copy MSGQ service\n");

	/* Setup the Zero Copy memory fill thread */
	ret = pthread_create(&msgq_thread, NULL, msgq_zcopy_service, NULL);
	if (ret)
		errx(1, "Failed to start shared fill service\n");

	/* Initialize TEE context */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEE initialization failed 0x%x", res);

	/* Open a session on Zero Copy TA */
	res = TEEC_OpenSession(&ctx, &sess, &ta_uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "Failed on open session on Zero Copy TA: 0x%x"
				"origin 0x%x", res, err_origin);

	/* Register this shared memory with TA */
	shared_mem_desc.buffer = zcopy.buf;
	shared_mem_desc.size   = mem_size;
	shared_mem_desc.flags  = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	res = TEEC_RegisterSharedMemory(&ctx, &shared_mem_desc);
	if (res != TEEC_SUCCESS)
		errx(1, "Failed to register shared memory");

	/*
	 * Prepare the operation parameters. It has only 1 with the information
	 * about the shared memory reference
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE,
					TEEC_NONE, TEEC_NONE);

	/* Invoke the command with shared memory buffer */
	op.params[0].memref.parent = &shared_mem_desc;
	op.params[0].memref.size   = mem_size;
	op.params[0].memref.offset = 0;
	res = TEEC_InvokeCommand(&sess, TA_ZERO_COPY_FILL_SHARED_MEM, &op,
			&err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "Fill shared mem failed 0x%x origin 0x%x",
						res, err_origin);

	TEEC_ReleaseSharedMemory(&shared_mem_desc);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	munmap(zcopy.buf, mem_size);

	/*
	 * FIXME: need to move from errx interface, because it will leak
	 * the message queue ID floating in the system.
	 */
	ree_service_exit(zcopy.msgq_hdl);

	/* Wait for service thread to close */
	pthread_join(msgq_thread, NULL);

	return 0;
}
