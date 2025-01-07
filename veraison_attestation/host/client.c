// SPDX-License-Identifier: BSD-3-Clause
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "client.h"

int find_psa_media_type_index(const ChallengeResponseSession *session) {
    for (int i = 0; i < session->accept_type_count; i++) {
        if (strcmp(session->accept_type_list[i], PSA_TYPE_NAME) == 0) {
            return i;
        }
    }
    return -1;
}

ChallengeResponseSession *open_session() {
    ChallengeResponseSession *session = NULL;
    const char *base_url = SERVER_BASE_URL;

    char new_session_endpoint[PATH_MAX] = {0};
    snprintf(new_session_endpoint, sizeof(new_session_endpoint),
             "%s/challenge-response/v1/newSession", base_url);

    /* Now run the challenge response session, using the discovered endpoint */
    VeraisonResult status = open_challenge_response_session(
        new_session_endpoint, 32, /* Nonce size */
        NULL, &session);

    if (status != Ok) {
        printf("Failed to allocate Veraison client session.\n");
        goto cleanup;
    }

    printf("\nOpened new Veraison client session at %s\n",
           session->session_url);
    printf("\nNumber of media types accepted: %d\n",
           (int)session->accept_type_count);
    for (size_t i = 0; i < session->accept_type_count; i++) {
        printf("\t%s\n", session->accept_type_list[i]);
    }
    printf("\nNonce size: %d bytes\n", (int)session->nonce_size);
    printf("Nonce: [");
    for (size_t i = 0; i < session->nonce_size; i++) {
        if (i > 0) {
            printf(", ");
        }
        printf("0x%x", session->nonce[i]);
    }
    printf("]\n");

    if (find_psa_media_type_index(session) == -1) {
        printf("There is no PSA in the list of media types, hence not "
               "supplying evidence.\n");
        goto cleanup;
    }

    printf("\nCompleted opening the session.\n\n");
    return session;

cleanup:
    if (session != NULL) {
        if (session->message != NULL) {
            printf("Error/log message: %s\n", session->message);
        }
        printf("Disposing client session.\n");
        free_challenge_response_session(session);
    }
    return NULL;
}

VeraisonResult post_evidence(ChallengeResponseSession *session,
                             unsigned char *evidence, size_t evidence_len) {
    printf("Supplying the generated evidence to the server.\n");

    /* Supply our evidence. */
    VeraisonResult status = challenge_response(
        session, evidence_len, evidence,
        session->accept_type_list[find_psa_media_type_index(session)]);

    if (status != Ok) {
        printf("Failed to supply evidence to server.\n");
        goto cleanup;
    }
    printf("\nReceived the attestation result from the server.\n");

    // And, finally, display the server's response, which will be a JWT
    // containing an EAR.
    printf("\nRaw attestation result (JWT): %s\n\n",
           session->attestation_result);

cleanup:
    if (session != NULL) {
        if (session->message != NULL) {
            printf("Error/log message: %s\n", session->message);
        }
        printf("Disposing client session.\n");
        free_challenge_response_session(session);
    }

    printf("\nCompleted sending the evidence and receiving the attestation "
           "result.\n");
    return (int)status;
}
