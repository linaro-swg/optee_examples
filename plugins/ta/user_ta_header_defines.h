/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2020, Open Mobile Platform LLC
 */

/*
 * The name of this file must not be modified
 */

#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

/* To get the TA UUID definition */
#include <plugin_ta.h>

#define TA_UUID PLUGIN_TA_UUID

/*
 * TA properties: multi-instance TA, no specific attribute
 */
#define TA_FLAGS 0

/* Provisioned stack size */
#define TA_STACK_SIZE (2 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE (32 * 1024)

/* The gpd.ta.version property */
#define TA_VERSION "1.0"

/* The gpd.ta.description property */
#define TA_DESCRIPTION \
	"Example of OP-TEE Trusted Application to work with plugin interface"

#endif /* USER_TA_HEADER_DEFINES_H */
