/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#ifndef __TA_HELLO_REE_H__
#define __TA_HELLO_REE_H__

/*
 * TA_HELLO_REE_UUID         : CA identifies UTA with this UUID
 * TA_HELLO_REE_MSGQ_REE_UUID: UTA identifies a REE service with this UUID
 * TA_HELLO_REE_DLL_REE_UUID : UTA identifies another REE service with this UUID
 *
 * UTA has no information if the REE service is implemented using POSIX Message
 * Queues or Dynamic Library interface. To UTA, a UUID uniquely identifies a REE
 * service whose parameters are negotiated using this header file
 */
#define TA_HELLO_REE_UUID		\
	{ 0x60eb5836, 0xfc9b, 0x446a,	\
		{ 0xb2, 0x77, 0x25, 0xb6, 0x50, 0xa8, 0x23, 0x8f} }

#define TA_HELLO_REE_MSGQ_REE_UUID	\
	{ 0x2e915163, 0xc41b, 0x44c9,	\
		{ 0x8d, 0xdc, 0x0a, 0xbf, 0x0b, 0x76, 0xfa, 0xf7} }

#define TA_HELLO_REE_DLL_REE_UUID	\
	{ 0x0e3ade56, 0x96dc, 0x44cf,	\
		{ 0x9b, 0x52, 0x2e, 0x6a, 0x06, 0xd8, 0x43, 0x80} }

/* Following is implemented by UTA */
#define TA_HELLO_REE_FILL_RANDOM_NUMBER		0

/* Following is implemented by REE */
#define HELLO_REE_EXCHANGE_GREETINGS			1

#endif
