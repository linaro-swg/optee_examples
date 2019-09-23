/*
 * Copyright (C) 2019 Intel Corporation All Rights Reserved
 */

#ifndef __TA_ZERO_COPY_H__
#define __TA_ZERO_COPY_H__

/*
 * TA_ZERO_COPY_UUID         : CA identifies UTA with this UUID
 */
#define TA_ZERO_COPY_UUID		\
	{ 0x94a03805, 0x5518, 0x4934,	\
		{ 0xa9, 0x8d, 0x49, 0xf7, 0x3e, 0x94, 0xce, 0x23} }

#define REE_ZERO_COPY_MSGQ_UUID		\
	{ 0xdc4b37ed, 0x5cf3, 0x467c,	\
		{ 0xa1, 0x6c, 0xfb, 0x12, 0x20, 0x20, 0x33, 0x0e} }

/* Following is implemented by UTA */
#define TA_ZERO_COPY_FILL_SHARED_MEM		0

/* Following is implemented by REE */
#define REE_ZERO_COPY_FILL_BUFFER		1

#endif
