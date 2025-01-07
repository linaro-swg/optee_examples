// SPDX-License-Identifier: BSD-3-Clause
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <string.h>

#include <pta_attestation.h>
#include <pta_veraison_attestation.h>
#include <veraison_attestation_ta.h>

TEE_Result call_pta_for_cbor_evidence(uint32_t param_types,
                                      TEE_Param params[4]) {
    TEE_TASessionHandle sess = TEE_HANDLE_NULL;
    TEE_UUID att_uuid = PTA_VERAISON_ATTESTATION_UUID;
    TEE_Result res = TEE_ERROR_GENERIC;
    uint32_t ret_orig = 0;

    res = TEE_OpenTASession(&att_uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
                            &ret_orig);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_OpenTASession failed\n");
        goto cleanup_return;
    }

    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_INOUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* Setup implementation ID */
    const uint8_t psa_implementation_id[IMPLEMENTATION_ID_LEN];
    memcpy((uint8_t *)psa_implementation_id, IMPLEMENTATION_ID,
           IMPLEMENTATION_ID_LEN);

    /* Forward params to PTA */
    uint32_t pta_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE);
    TEE_Param pta_params[4] = {{.memref.buffer = params[0].memref.buffer,
                                .memref.size = params[0].memref.size},
                               {.memref.buffer = params[1].memref.buffer,
                                .memref.size = params[1].memref.size},
                               {.memref.buffer = psa_implementation_id,
                                .memref.size = IMPLEMENTATION_ID_LEN},
                               {.memref.buffer = NULL, .memref.size = 0}};

    res = TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE,
                              PTA_VERAISON_ATTESTATION_GET_CBOR_EVIDENCE,
                              pta_param_types, pta_params, &ret_orig);
    if (res != TEE_SUCCESS) {
        EMSG("TEE_InvokeTACommand failed\n");
        goto cleanup_return;
    }
    /* Update buffer size actually used　*/
    params[1].memref.size = pta_params[1].memref.size;

cleanup_return:
    TEE_CloseTASession(sess);
    return res;
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/
TEE_Result TA_CreateEntryPoint(void) {
    /* Nothing to do */
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
    /* Nothing to do */
    return;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param __unused params[4],
                                    void __unused **sess_ctx) {
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx) {
    /* Nothing to do */
    return;
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx, uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4]) {
    switch (cmd_id) {
    case TA_VERAISON_ATTESTATOIN_CMD_GEN_CBOR_EVIDENCE:
        return call_pta_for_cbor_evidence(param_types, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
