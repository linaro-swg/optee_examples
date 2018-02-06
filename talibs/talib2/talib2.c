// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <stdio.h>
#include "talib2.h"
#include "talib3.h"

void talib2_func(void)
{
	printf("talib2_func()\n");
	talib3_func();
}
