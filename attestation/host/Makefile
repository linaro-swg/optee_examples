
.PHONY: all
all:
	$(MAKE) -C client CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables
	$(MAKE) -C set_data CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables

.PHONY: clean
clean:
	$(MAKE) -C client clean
	$(MAKE) -C set_data clean