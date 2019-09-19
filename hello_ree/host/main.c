/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * o A Client Application (CA) requests the User Trusted Application (UTA)
 *   service by invoking TEEC_xx calls.
 *
 * o UTA may in turn require Rich Execution Environment (REE) services in order
 *   to fulfill the CA request. The REE service could be storage or generically,
 *   anything not supported by tee-supplicant.
 *
 * o This application uses two available solutions to provide service to TEE.
 *   It is based on using a UUID in the reverse direction (UTA -> CA)
 *   - Posix Message Queues: Message Queue is transparent to the caller.
 *
 *   - Dynamic Library     : The library needs to be developed with a specific
 *                           function signature and compiled as .so and placed
 *                           in a PATH (/lib64) where tee-supplicant can find
 *                           it.
 *
 * For the service to invoked, it is expected that tee-supplicant is executing
 * with permission to access /data folder, otherwise, invocation will fail and
 * TA will receive a failure.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <hello_ree_ta.h>

/* OP-TEE REE client API to provide service to TEE */
#include <ree_service_api.h>

/**
 * ree_msgq_service() - Message Queue based service handler
 */
void *ree_msgq_service(void *arg)
{
	int ret;
	void *ree_srvc_msgq_hdl = arg;
	size_t num_params;
	struct tee_params params[4] = {0};

	/* Process the message */
	do {
		/* Wait for the message */
		ret = ree_service_rcv(ree_srvc_msgq_hdl, &num_params, params);
		if (ret) {
			printf("Failed to receive msg\n");
			goto err;
		}

		/* TODO: Check for the parameter count */
		switch(params[0].u.value.a) {
		case HELLO_REE_EXCHANGE_GREETINGS:
		{
			char *msg = "Hello! from MSGQ";
			memcpy(params[2].u.memref.buffer, msg, strlen(msg) + 1);
			printf("msgq: Received: %s\n",
					(char *)params[1].u.memref.buffer);
			break;
		}

		/* Setup the service for receiving next commands */
		case OPTEE_MRC_REE_SERVICE_START:
			printf("msgq: Nothing specific to start\n");
			break;

		/* Shutdown the service */
		case OPTEE_MRC_REE_SERVICE_STOP:
			printf("msgq: Nothing specific to stop\n");
			break;

		default:
			printf("msgq: Unknown command received: %lu\n",
							params[0].u.value.a);
			break;
		}

		/* Send the response */
		ret = ree_service_snd(ree_srvc_msgq_hdl, num_params, params, 0);
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
	pthread_t ree_msgq_thread;
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_HELLO_REE_UUID;
	TEEC_UUID msgq_ree_uuid = TA_HELLO_REE_MSGQ_REE_UUID;
	uint32_t err_origin;
	void *ree_srvc_msgq_hdl;

	/* Start the Message Queue based REE service */
	ret = ree_service_init(&msgq_ree_uuid, &ree_srvc_msgq_hdl);
	if (ret)
		errx(1, "Failed to register Hello REE MSQ service\n");

	/* Listen to the service messages from UTA */
	ret = pthread_create(&ree_msgq_thread, NULL,
			ree_msgq_service, ree_srvc_msgq_hdl);
	if (ret)
		errx(1, "Failed to start hello world ree service\n");

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session to the "hello ree" TA */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
				res, err_origin);

	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're requesting a Random number from TA
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
			TEEC_NONE, TEEC_NONE);

	/* Get a 4 byte random number from TA */
	printf("Invoking TA to fill random number %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_HELLO_REE_FILL_RANDOM_NUMBER, &op,
			&err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
	printf("TA returned random number as %u\n", op.params[0].value.a);

	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	/* Close down the message queue based REE service */
	/*
	 * FIXME: need to move from errx interface, because it will leak
	 * the message queue ID floating in the system.
	 */
	ree_service_exit(ree_srvc_msgq_hdl);

	/* Wait for the listening thread to exit */
	pthread_join(ree_msgq_thread, NULL);

	return 0;
}
