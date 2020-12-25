// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Elias von Däniken
 */

#ifndef __TA_SAMPLE_ATTESTATION_H__
#define __TA_SAMPLE_ATTESTATION_H__

#define TA_SAMPLE_ATTESTATION_UUID \
	{ 0xc615b83b, 0xc264, 0x4bd7, \
		{ 0x8a, 0x8c, 0x8b, 0x08, 0xa5, 0x93, 0x50, 0xdb} }

/* The function IDs implemented in this TA */
#define ATTESTATION			0
#define GEN_NEW_KEY			1
#define INCREMENT			2
#define COUNTER_CERT		3

#endif // ifndef __TA_SAMPLE_ATTESTATION_H__
