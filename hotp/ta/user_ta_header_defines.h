/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* The name of this file must not be modified */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

 /* To get the TA_HOTP_UUID define */
#include <hotp_ta.h>

#define TA_UUID		TA_HOTP_UUID

#define TA_FLAGS	TA_FLAG_EXEC_DDR

/* Provisioned stack size */
#define TA_STACK_SIZE	(2 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE	(32 * 1024)

#endif
