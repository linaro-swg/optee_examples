/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <sdm_crypt_ta.h>

#define TA_UUID			TA_SDM_CRYPT_UUID

#define TA_FLAGS		(TA_FLAG_SINGLE_INSTANCE | \
				 TA_FLAG_MULTI_SESSION | \
				 TA_FLAG_INSTANCE_KEEP_ALIVE)

#define TA_STACK_SIZE		(4 * 1024)

#define TA_DATA_SIZE		(128 * 1024)

#define TA_VERSION		"1.0"
#define TA_DESCRIPTION		"Intel SDM SDOS encrypt/decrypt wrapper TA (PTA_SDM_SVC)"

#define TA_CURRENT_TA_EXT_PROPERTIES \
	{ "com.intel.optee.examples.sdm_crypt.description", \
	  USER_TA_PROP_TYPE_STRING, \
	  "Validates and forwards SDOS encrypt/decrypt to PTA_SDM_SVC" }

#endif /* USER_TA_HEADER_DEFINES_H */
