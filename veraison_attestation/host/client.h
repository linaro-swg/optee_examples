// SPDX-License-Identifier: BSD-3-Clause
#ifndef CLIENT_H
#define CLIENT_H

#include "veraison_client_wrapper.h"

#define SERVER_BASE_URL "http://relying-party-service:8087"
#define PSA_TYPE_NAME   "application/psa-attestation-token"

ChallengeResponseSession *open_session();
VeraisonResult post_evidence(ChallengeResponseSession *session,
                             unsigned char *evidence, size_t evidence_len);

#endif // CLIENT_H
