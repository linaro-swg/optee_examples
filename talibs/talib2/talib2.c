// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <stdio.h>
#include <tee_internal_api.h>
#include "talib2.h"
//#include "talib3.h"

void talib2_func(void)
{
	printf("talib2_func()\n");
//	talib3_func();
}

void talib2_panic(void)
{
	printf("Calling TEE_Panic(0)\n");
	TEE_Panic(0);
}
