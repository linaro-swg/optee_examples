Basics for Development of OP-TEE Trusted Applications
=====================================================

This document show how to implement a basic trusted application for OP-TEE,
using the OP-TEE devkit to build and sign the trusted application binary.

In this document, a trusted application running in the OP-TEE os is referred
to as a TA.

### Contents
1. [TA Minimal Source Files](#1-ta-minimal-source-files)
2. [TA Makefile Script Basics](#2-ta-makefile-script-basics)
3. [Android Build Environment](#3-android-build-environment)
4. [TA Entry Points Implementation Basics](#4-ta-entry-points-implementation-basics)
5. [TA Properties Basics](#5-ta-properties-basics)
6. [Specific cares on TA invocation parameters](#6-specific-cares-on-ta-invocation-parameters)


---
# 1. TA Minimal Source Files

Trusted Application Makefile must be designed to rely on OP-TEE devkit
resources in order to successfully build the target application. The OP-TEE
devkit is built (maybe installed) when one builds (installs) the optee_os.

To build a TA, one must provide:

- **Makefile**, a make script that should set some configuration variables and
  include the devkit make script.

- **sub.mk**, a make script that lists the sources to build (local source files,
  subdirectories to parse, source file specific build directives).

- **user_ta_header_defines.h**, a specific ANSI-C header file to define most of
  the TA properties.

- A implementation of at least the TA entry points, as extern functions:
    `TA_CreateEntryPoint()`, `TA_DestroyEntryPoint()`,
    `TA_OpenSessionEntryPoint()`, `TA_CloseSessionEntryPoint()`,
    `TA_InvokeCommandEntryPoint()`

Looking at example hello_world:
```
hello_world/
├── ...
└── ta
    ├── Makefile                  BINARY=<uuid>
    ├── Android.mk                Android way to invoke the Makefile
    ├── sub.mk                    srcs-y += hello_world_ta.c
    ├── include
    │   └── hello_world_ta.h      Header exported to non-secure: TA commands API
    ├── hello_world_ta.c          Implementation of TA entry points
    └── user_ta_header_defines.h  TA_UUID, TA_FLAGS, TA_DATA/STACK_SIZE, ...
```

---
# 2. TA Makefile Script Basics

## 2.1. Devkit Makefile Requirements

The devkit make script is located in the devkit filetree at path
**mk/ta_dev_kit.mk**.

The make script supports rules `all` and `clean` to build a TA or
a library and clean the built objects.

The make script expects some configuration variables:

- Variable `TA_DEV_KIT_DIR`

  Base directory of the devkit. Used the devkit itself to locate its tools.

- Variables `BINARY` and `LIBNAME`

  `BINARY` and `LIBNAME` are exclusives.

  If building a TA, `BINARY` shall provide the TA filename used to load the TA.
  The built signed TA binary file will be named `${BINARY}.ta`.
  In native OP-TEE, it is the TA uuid, used by tee-supplicant to identify TAs.

  if building a static library (that will be later linked by a TA),
  `LIBNAME` shall provide the name of the library. The generated library
  binary file will be named `lib${LIBNAME}.a`

- Variables `CROSS_COMPILE` and `CROSS_COMPILE32`

  Cross compiler for the TA or the library source files. `CROSS_COMPILE32`
  is optional. It allows to target AArch32 builds on AArch64 capable systems.
  On AArch32 systems, `CROSS_COMPILE32` defaults to `CROSS_COMPILE`.

Some optional configuration variables can be supported, check optee_os
delivery. For examples:

- Variable `O`

  Base directory for build objects filetree. If not set, devit defaults to
  **./out** from the TA source tree base directory.

A typical makefile to drive the build of a TA is:
```make
# Append specific configuration to the C source build (here log=info)
# The UUID for the Trusted Application
BINARY=8aaaf200-2450-11e4-abe2-0002a5d5c51b

# Source the devkit make script
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
```

## 2.2. Listing Source Files to Build and Build directives

The make script expects that current directory contains a file `sub.mk` that
is the entry point for listing the source files to build and other specific
build directives.

Following are examples of directive one can implement in a sub.mk make script:

* `srcs-y += hello_world_ta.c`\
  Adds **./hello_world_ta.c** from current directory to the list of the source
  file to build and link.

* `global-incdirs-y += include/`\
  Includes path **./include/** from the current directory to the include path.

* `cflags-hello_world_ta.c-y += -Wno-strict-prototypes`\
  Adds directive `-Wno-strict-prototypes` to the build directive of
  **./hello_world_ta.c** specific source file.

* `cflags-remove-hello_world_ta.c-y += -Wno-strict-prototypes`\
  Removes directive `-Wno-strict-prototypes` from the build directives of
  **./hello_world_ta.c** specific source file.

* `libnames += foo`\
  Adds the static library `foo` to the list of the linker directives:
  `-lfoo`.

* `libdirs += path/to/libfoo/install/directory`\
  Adds the directory path to the libraries pathes list. Archive file
  **libfoo.a** is expectd in this directory.

* `libdeps += path/to/greatlib/libgreatlib.a`\
  Adds the static library binary to the TA build dependencies.

---
# 3. Android Build Environment

OP-TEE devkit supports building in Android build environment. One can
implement an Android.mk script for its TA next to the Makefile script.

The Android build will parse the TA Android make script which will parse a
devkit Android make script to locate TA build resources. Then the Android
build will execute a `make` command to built the TA through its generic
Makefile script.

A typical Android.mk script for a TA is:
```make
$ cat hello_world/ta/Android.mk
# Define base path for the TA sources filetree
LOCAL_PATH := $(call my-dir)
# Define the module name as the signed TA binary filename.
local_module := 8aaaf200-2450-11e4-abe2-0002a5d5c51b.ta
# Include the devkit Android make script
include $(OPTEE_OS_DIR)/mk/aosp_optee.mk
```

---
# 4. TA Entry Points Implementation Basics

TA source code is expected to provide implementation for the following
functions:

```c
TEE_Result TA_CreateEntryPoint(void)
{
	/* Allocate some resources, init something, ... */
	...

	/* Return with a status */
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	/* Release resources if required before TA destruction */
	...
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t ptype,
				    TEE_Param param[4],
				    void **session_id_ptr)
{
	/* Check client identity, and alloc/init some session resources if any */
	...

	/* Return with a status */
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ptr)
{
	/* check client and handle session resource release, if any */
	...
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_id,
				      uint32_t command_id,
				      uint32_t parameters_type,
				      TEE_Param parameters[4])
{
	/* Decode the command and process execution of the target service */
	...

	/* Return with a status */
	return TEE_SUCCESS;
}
```

---
# 5. TA Properties Basics

Trusted Application properties shall be defined in a specific ANSI-C header
file named **user_ta_header_defines.h**. The header file shall define the following macros:

- `TA_UUID` defines the TA uuid value

- `TA_FLAGS` define some of the TA properties

- `TA_STACK_SIZE` defines the RAM size to be reserved for TA stack

- `TA_DATA_SIZE` defines the RAM size to be reserved for TA heap (TEE_Malloc() pool)

Refer to [TA properties] to configure these macros.

**user_ta_header_defines.h** file may provide the following macro:

- `TA_CURRENT_TA_EXT_PROPERTIES` may define extra properties of the TA.


Example of **user_ta_header_defines.h**:

```c
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#define TA_UUID
	{ 0x8aaaf200, 0x2450, 0x11e4, \
		{ 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b} }

#define TA_FLAGS			(TA_FLAG_EXEC_DDR | \
						TA_FLAG_SINGLE_INSTANCE | \
						TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE			(2 * 1024)
#define TA_DATA_SIZE			(32 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
	{ "gp.ta.description", USER_TA_PROP_TYPE_STRING, "Foo TA for some purpose." }, \
	{ "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0100 } }

#endif /* USER_TA_HEADER_DEFINES_H */
```

---
# 6. Specific cares on TA invocation parameters

GPD TEE Client APIs `TEEC_InvokeCommand()` and `TEE_OpenSession()` allow a client
to invoke a TA with some invocation parameters: values or references to memory buffers.

It is mandatory that TAs verify the parameters types before using the parameters
themsleves.

TA can rely on macro TEE_PARAM_TYPE_GET(param_type, param_index)` to get the
type of a parameter and check its value according to the expected parameter.

For example, if TA expect that command ID 0 comes with param#0 being a input
value, param#2 being a output value, and param#3 being a in/out memory
reference (buffer), TA should implemented the following sequence:

```c
TEE_Result handle_command_0(void *session, uint32_t cmd_id,
			    uint32_t param_types, TEE_Param params[4])
{
	if ((TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_VALUE_IN) ||
	    (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_VALUE_OUT) ||
	    (TEE_PARAM_TYPE_GET(param_types, 2) != TEE_PARAM_TYPE_MEMREF_INOUT) ||
	    (TEE_PARAM_TYPE_GET(param_types, 3) != TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS
	}

	/* process command */
	...
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t command_id,
				      uint32_t param_types, TEE_Param params[4])
{
	switch (command_id) {
	case 0:
		return handle_command_0(session, param_types, params);
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}
}
```

[TA properties]: ./TA_properties.md
