/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#include <stdio.h>
#include <string.h>

#include <hello_ree_ta.h>
#include <tee_client_api.h>
#include <ree_service_api.h>

/**
 * process_tee_params() - dynamic library interface
 * This implements the Dynamic Library based REE service. The function
 * signature is fixed and needs to be implemented to provide service to
 * UTA
 */
TEEC_Result process_tee_params(size_t num_params, struct tee_params *params)
{
	switch (params[0].u.value.a) {
	case HELLO_REE_EXCHANGE_GREETINGS:
	{
		char *msg = "Hello! from DLL";
		memcpy(params[2].u.memref.buffer, msg, strlen(msg) + 1);
		printf("dll: Received: %s\n", (char *)params[1].u.memref.buffer);
		break;
	}

	case OPTEE_MRC_REE_SERVICE_START:
		printf("dll: Nothing specific to start\n");
		break;

	case OPTEE_MRC_REE_SERVICE_STOP:
		printf("dll: Nothing specific to stop\n");
		break;

	default:
		printf("dll: Unknown command received: %lu\n", params[0].u.value.a);
		break;
	}

	return 0;
}
