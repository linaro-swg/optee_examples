// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#include <assert.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/* This TA header */
#include <plugin_ta.h>

#include <string.h>
#include <stdint.h>

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __maybe_unused params[4],
				    void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
}

static TEE_Result syslog_plugin_ping(void)
{
	int n = 0;
	TEE_Result res = TEE_SUCCESS;
	static uint32_t inc_var = 0;
	char log_str[64] = { 0 };
	TEE_UUID syslog_uuid = SYSLOG_PLUGIN_UUID;

	n = snprintf(log_str, sizeof(log_str), "Hello, plugin! value = 0x%x",
		     inc_var++);
	if (n > (int)sizeof(log_str))
		return TEE_ERROR_GENERIC;

	IMSG("Push syslog plugin string \"%s\"", log_str);

	res = tee_invoke_supp_plugin(&syslog_uuid, TO_SYSLOG_CMD, LOG_INFO,
				     log_str, n, NULL);
	if (res)
		EMSG("invoke plugin failed with code 0x%x", res);

	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param __unused params[4])
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	switch (cmd_id) {
	case PLUGIN_TA_PING:
		return syslog_plugin_ping();
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
