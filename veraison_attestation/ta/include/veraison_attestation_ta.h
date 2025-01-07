#ifndef TA_VERAISON_ATTESTATION_H
#define TA_VERAISON_ATTESTATION_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_VERAISON_ATTESTATION_UUID                                           \
    {                                                                          \
        0xa6b53b34, 0x855f, 0x11ee, {                                          \
            0xb9, 0xd1, 0x02, 0x42, 0xac, 0x12, 0x00, 0x02                     \
        }                                                                      \
    }

/* The function ID(s) implemented in this TA */
#define TA_VERAISON_ATTESTATOIN_CMD_GEN_CBOR_EVIDENCE 0

/* Implementation ID used in PSA evidence */
#define IMPLEMENTATION_ID     "acme-implementation-id-000000001"
#define IMPLEMENTATION_ID_LEN 32

#if defined(HOST_BUILD)
typedef TEEC_UUID UUID_TYPE;
#else
typedef TEE_UUID UUID_TYPE;
#endif

#endif /*TA_VERAISON_ATTESTATION_H*/
