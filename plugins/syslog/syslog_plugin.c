// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

#include <stddef.h>
#include <syslog.h>
#include <tee_plugin_method.h>

/*
 * OPTEE has access to the plugin by the UUID
 */
#define SYSLOG_PLUGIN_UUID { 0x96bcf744, 0x4f72, 0x4866, \
		{ 0xbf, 0x1d, 0x86, 0x34, 0xfd, 0x9c, 0x65, 0xe5 } }

/* plugin cmd */
#define TO_SYSLOG 0

static TEEC_Result syslog_plugin_init(void)
{
	return TEEC_SUCCESS;
}

static TEEC_Result write_syslog(unsigned int sub_cmd, void *data, size_t data_len)
{
	/* 'sub_cmd' in this case means priority according syslog.h */
	openlog(NULL, LOG_CONS | LOG_PID, LOG_DAEMON);
	syslog(sub_cmd, "%.*s", (int)data_len, (const char *)data);
	closelog();

	return TEEC_SUCCESS;
}

static TEEC_Result syslog_plugin_invoke(unsigned int cmd, unsigned int sub_cmd,
					void *data, size_t data_len,
					size_t *out_len)
{
	/*
	 * The pointer 'out_len' is used to save length of
	 * output data from the plugin for TEE, when TEE will be needed
	 * by the data.
	 *
	 * Buffer 'data' is used like input and output.
	 */
	(void)out_len;

	switch (cmd) {
	case TO_SYSLOG:
		return write_syslog(sub_cmd, data, data_len);
	default:
		break;
	}

	return TEEC_ERROR_NOT_SUPPORTED;
}

struct plugin_method plugin_method = {
	"syslog",
	SYSLOG_PLUGIN_UUID,
	syslog_plugin_init, /* can be NULL */
	syslog_plugin_invoke,
};
