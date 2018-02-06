// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <stdio.h>
#include <talib1.h>
#include <talib2.h>
#include <talib3.h>
#include <tee_internal_api.h>

TEE_Result TA_CreateEntryPoint(void)
{
	printf("TA_CreateEntryPoint()\n");

	/* This function is in the static library libtalib1.a */
	talib1_func();
	/*
	 * This one is in the shared library libtalib2.so (the run-time
	 * binary loaded by OP-TEE is 7814a949-e967-421c-8838-04f7ee1c5744.ta)
	 */
	talib2_func();
	/*
	 * And this one is in libtalib3.so (a.k.a.
	 * 14c7f8d4-0202-4bfe-b4ca-ab6eca303169.ta). ta_lib3func() is also
	 * called from within libtalib2.
	 */
	talib3_func();

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
		TEE_Param __unused params[4],
		void __unused **sess_ctx)
{
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
			uint32_t __unused cmd_id,
			uint32_t __unused param_types,
			TEE_Param __unused params[4])
{
	return TEE_ERROR_BAD_PARAMETERS;
}
