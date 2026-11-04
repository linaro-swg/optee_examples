/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <sdm_efuse_reload_cache_ta.h>

#define TA_UUID			TA_SDM_EFUSE_RELOAD_CACHE_UUID

#define TA_FLAGS		(TA_FLAG_SINGLE_INSTANCE | \
				 TA_FLAG_MULTI_SESSION | \
				 TA_FLAG_INSTANCE_KEEP_ALIVE)

#define TA_STACK_SIZE		(2 * 1024)
#define TA_DATA_SIZE		(32 * 1024)

#define TA_VERSION		"1.0"
#define TA_DESCRIPTION		"Intel SDM eFuse cache reload wrapper TA"

#define TA_CURRENT_TA_EXT_PROPERTIES \
	{ "com.intel.optee.examples.sdm_efuse_reload_cache.description", \
	  USER_TA_PROP_TYPE_STRING, \
	  "Reloads the SDM eFuse cache via PTA_SDM_SVC" }

#endif /* USER_TA_HEADER_DEFINES_H */
