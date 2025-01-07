// SPDX-License-Identifier: BSD-3-Clause
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <veraison_attestation_ta.h>

#include "client.h"

void print_binary_in_hex(uint8_t *buf, size_t sz) {
    int i = 0;
    for (i = 0; i < sz; i++)
        fprintf(stdout, "%02x", buf[i]);

    printf("\n");

    return;
}

int main(int argc, char *argv[]) {
    TEEC_Result res = TEEC_SUCCESS;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID ta_uuid = TA_VERAISON_ATTESTATION_UUID;
    uint32_t err_origin;

    /* Initialize a context connecting us to the TEE */
    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

    res = TEEC_OpenSession(&ctx, &sess, &ta_uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
                           &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res,
             err_origin);

    /* Connect to the server and establish a session */
    ChallengeResponseSession *session = open_session();
    if (session == NULL) {
        printf("Failed to open session.\n");
        return 1;
    }

    /* Request TA to issue evidence based on a given nonce */
    /* The buffer allocated here must be large enough to hold the CBOR evidece
     */
    uint8_t cbor_evidence[1024] = {0};
    TEEC_Operation op = {0};
    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE);
    op.params[0].tmpref.buffer = (uint8_t *)session->nonce;
    op.params[0].tmpref.size = session->nonce_size;
    op.params[1].tmpref.buffer = &cbor_evidence;
    op.params[1].tmpref.size = sizeof(cbor_evidence);

    printf("\nInvoke TA.\n");
    res = TEEC_InvokeCommand(&sess, TA_VERAISON_ATTESTATOIN_CMD_GEN_CBOR_EVIDENCE,
                             &op, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res,
             err_origin);

    printf("Invoked TA successfully.\n\n\n");

    /* Receive CBOR(COSE) evidence from PTA */
    printf("Received evidence of CBOR (COSE) format from PTA.\n\n");

    printf("CBOR(COSE) size: %ld\n", op.params[1].tmpref.size);
    printf("CBOR(COSE): ");
    print_binary_in_hex(op.params[1].tmpref.buffer, op.params[1].tmpref.size);
    printf("\n\n");

    /* Send the generated evidence to the session just established */
    post_evidence(session, op.params[1].tmpref.buffer,
                  op.params[1].tmpref.size);

    return 0;
}
