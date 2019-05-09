#include <stdio.h>
#include <string.h>

#include <hello_world_ta.h>
#include <tee_client_api.h>
#include <ree_service_api.h>

TEEC_Result process_tee_params(size_t num_params, struct tee_params *params)
{
	switch (params[0].u.value.a) {
	case HELLO_WORLD_MSG:
	{
		char *msg = "Hello! from REE";
		memcpy(params[2].u.memref.buffer, msg, strlen(msg) + 1);
		printf("DLSO: Received: %s\n", (char *)params[1].u.memref.buffer);
		break;
	}

	case OPTEE_MRC_GENERIC_SERVICE_START:
		printf("DLSO: Nothing specific to start\n");
		break;

	case OPTEE_MRC_GENERIC_SERVICE_STOP:
		printf("DLSO: Nothing specific to stop\n");
		break;

	default:
		printf("DLSO: Unknown command received: %lu\n", params[0].u.value.a);
		break;
	}

	return 0;
}
