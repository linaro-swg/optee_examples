/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

/*
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

 /* To get the TA_RANDOM_EXAMPLE_UUID define */
#include <random_ta.h>

#define TA_UUID				TA_RANDOM_UUID

/* TA properties: multi-instance TA, no specific attribute */
#define TA_FLAGS			0

/* Provisioned stack size */
#define TA_STACK_SIZE			(2 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE			(32 * 1024)

/* The gpd.ta.version property */
#define TA_VERSION	"1.0"

/* The gpd.ta.description property */
#define TA_DESCRIPTION	"Example of how a TA can get a buffer of random bytes"

#endif /* USER_TA_HEADER_DEFINES_H */
