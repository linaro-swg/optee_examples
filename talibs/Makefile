export V?=0

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

.PHONY: all
all:
	$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)"
	$(MAKE) -C talib1 CROSS_COMPILE="$(TA_CROSS_COMPILE)" LDFLAGS=""
	$(MAKE) -C talib3 CROSS_COMPILE="$(TA_CROSS_COMPILE)" LDFLAGS=""
	$(MAKE) -C talib2 CROSS_COMPILE="$(TA_CROSS_COMPILE)" LDFLAGS=""
	$(MAKE) -C ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" LDFLAGS=""

.PHONY: clean
clean:
	$(MAKE) -C host clean
	$(MAKE) -C talib1 clean
	$(MAKE) -C talib3 clean
	$(MAKE) -C talib2 clean
	$(MAKE) -C ta clean
