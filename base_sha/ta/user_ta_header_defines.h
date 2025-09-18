/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2025, Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <base_sha_ta.h>

#define TA_UUID				TA_BASE_SHA_UUID

#define TA_FLAGS			TA_FLAG_EXEC_DDR

/* Provisioned stack size */
#define TA_STACK_SIZE			(2 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE			(32 * 1024)

/* The gpd.ta.version property */
#define TA_VERSION	"1.0"

/* The gpd.ta.description property */
#define TA_DESCRIPTION	"Example of TA using an basic SHA sequence"

#endif /*USER_TA_HEADER_DEFINES_H*/
