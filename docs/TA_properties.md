Defining Properties of Trusted Applications
===========================================

This document is related to the trusted application examples documentation [TA basics].


### Contents

1. [TA properties defined by GPD TEE specifications](#1-ta-properties-defined-by-gpd-tee-specifications)
2. [TA Property Flags from the OP-TEE Extensions](#2-ta-property-flags-from-the-op-tee-extensions)


# 1. TA properties defined by GPD TEE specifications

Standard TA properties must be defined through property flag in macro
`TA_FLAGS` by **user_ta_header_defines.h**.

## 1.1. Single Instance Property

`"gpd.ta.singleInstance"` is a boolean property of the TA.

This property defines if one instance of the TA must be created and will
receive all open session request, or if a new specific TA instance must be
created for each incoming open session request.

OP-TEE TA flag `TA_FLAG_SINGLE_INSTANCE` sets to configuration of this
property.

The boolean property is set to `true` if `TA_FLAGS` sets bit
`TA_FLAG_SINGLE_INSTANCE`, otherwise the boolean property is set to `false`.

## 1.2. Multi-session Property

`"gpd.ta.multiSession"` is a boolean property of the TA.

This property defines if the TA instance can handle several sessions. If
disabled, TA instance support only one session. In such case, if the TA
already has a opened session, any open session request will return with a
busy error status.

This property is meaningless if TA is NOT SingleInstance.

OP-TEE TA flag `TA_FLAG_MULTI_SESSION` sets to configuration of this
property.

The boolean property is set to `true` if `TA_FLAGS` sets bit
`TA_FLAG_MULTI_SESSION`, otherwise the boolean property is set to `false`.

## 1.3. Keep Alive Property

`"gpd.ta.instanceKeepAlive"` is a boolean property of the TA.

This property defines if the TA instance created must be destroyed or not when
all sessions opened towards the TA are closed. If the property is enabled, TA
instance, once created (at 1st open session request), is never removed unless
the TEE itself is restarted (boot/reboot).

This property is meaningless if TA is NOT SingleInstance.

OP-TEE TA flag `TA_FLAG_INSTANCE_KEEP_ALIVE` sets to configuration of this
property.

The boolean property is set to `true` if `TA_FLAGS` sets bit
`TA_FLAG_INSTANCE_KEEP_ALIVE`, otherwise the boolean property is set to `false`.

## 1.4. Heap Size Property

`"gpd.ta.dataSize"` is a 32bit integer property of the TA.

This property defines the size in bytes of the TA allocation pool, in which
`TEE_Malloc()` and friends allocate memory.

The value of the property must be defined by the macro `TA_DATA_SIZE` from
**user_ta_header_defines.h**.

## 1.5. Stack Size Property

`"gpd.ta.stackSize"` is a 32bit integer property of the TA.

This property defines the size in bytes of the stack used for TA execution.

The value of the property must be defined by the macro `TA_STACK_SIZE` from
**user_ta_header_defines.h**.

# 2. TA Property Flags from the OP-TEE Extensions

## 2.1. User Mode Property Flag

`TA_FLAG_USER_MODE` is a bit flag supported by `TA_FLAGS`.

This property flag is currently meaningless in OP-TEE. It may be set or not
without impact on TA execution. All OP-TEE TAs are executed in user mode/level.

Because of this we do not recommend to use this flag.

## 2.2. Exec-in-DDR Property Flag

`TA_FLAG_EXEC_DDR` is a bit flag supported by `TA_FLAGS`.

This property flag is currently meaningless in OP-TEE. Nevertheless it shall
be set. It is a legacy property flag that aimed at targeting location for the TA
execution, internal RAM or external DDR.

Therefore all TAs must set `TA_FLAG_EXEC_DDR` in `TA_FLAGS` in their
**user_ta_header_defines.h** header file.

Note: this flag will soon be deprecated.

## 2.3. Secure Data Path Support Property Flag

`TA_FLAG_SECURE_DATA_PATH` is a bit flag supported by `TA_FLAGS`.

This property flag claims the secure data support from the OP-TEE OS for the TA.
Refer to the OP-TEE OS for secure data path support.

TAs that do not set `TA_FLAG_SECURE_DATA_PATH` in the value of `TA_FLAGS` will
not be able to handle memory reference invocation parameters that relate to
secure data path buffers.

## 2.4. Remap Support Property Flag

`TA_FLAG_REMAP_SUPPORT` is a bit flag supported by `TA_FLAGS`.

This property flag is currently meaningless in OP-TEE and therefore we
recommend to not use this flag.

Note: this flag will soon be deprecated.

## 2.5. Cache maintenance Property Flag

`TA_FLAG_CACHE_MAINTENANCE` is a bit flag supported by `TA_FLAGS`.

This property flag claims access to the cache maintenance API for the TA:
`TEE_CacheXxxx()`. Refer to the OP-TEE to check if cache API support is
enabled.

TAs that do not set `TA_FLAG_CACHE_MAINTENANCE` in the value of their `TA_FLAGS`
will not be able to call the cache maintenance API.

[TA basics]: ./TA_basics.md
