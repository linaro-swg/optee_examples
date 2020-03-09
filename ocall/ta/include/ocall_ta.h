/*
 * Copyright (c) 2020, Microsoft Corporation
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef TA_OCALL_H
#define TA_OCALL_H

/* 9b2c0652-3b9b-4d83-971e-e56c40512793 */
#define TA_OCALL_UUID \
		{ 0x9b2c0652, 0x3b9b, 0x4d83, \
			{ 0x97, 0x1e, 0xe5, 0x6c, 0x40, 0x51, 0x27, 0x93 } }

#define TA_OCALL_CMD_CALL_CA	0

#define CA_OCALL_CMD_REPLY_SESSION_OPEN	99
#define CA_OCALL_CMD_REPLY_TA		100

#endif /*TA_OCALL_H*/
