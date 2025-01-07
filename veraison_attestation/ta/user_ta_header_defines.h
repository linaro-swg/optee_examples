// SPDX-License-Identifier: BSD-3-Clause
/*
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

/* To get the TA UUID definition */
#include <veraison_attestation_ta.h>

#define TA_UUID TA_VERAISON_ATTESTATION_UUID

/*
 * TA properties: multi-instance TA, no specific attribute
 * TA_FLAG_EXEC_DDR is meaningless but mandated.
 */
#define TA_FLAGS TA_FLAG_EXEC_DDR

/* Provisioned stack size */
#define TA_STACK_SIZE (2 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE (32 * 1024)

#endif /* USER_TA_HEADER_DEFINES_H */
