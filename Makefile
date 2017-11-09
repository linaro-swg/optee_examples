export V ?= 0

OUTPUT_DIR := $(CURDIR)/out

EXAMPLE_LIST := hello_world
EXAMPLE_LIST += random

.PHONY: all
all: examples prepare-for-rootfs

.PHONY: clean
clean: examples-clean prepare-for-rootfs-clean

examples:
	@for example in $(EXAMPLE_LIST); do \
		$(MAKE) -C $$example CROSS_COMPILE="$(HOST_CROSS_COMPILE)"; \
	done

examples-clean:
	@for example in $(EXAMPLE_LIST); do \
		$(MAKE) -C $$example clean; \
	done

prepare-for-rootfs: examples
	@echo "Copying example CA and TA binaries to $(OUTPUT_DIR)..."
	@mkdir -p $(OUTPUT_DIR)
	@mkdir -p $(OUTPUT_DIR)/ta
	@mkdir -p $(OUTPUT_DIR)/ca
	@for example in $(EXAMPLE_LIST); do \
		if [ -e $$example/host/optee_example_$$example ]; then \
			cp -p $$example/host/optee_example_$$example $(OUTPUT_DIR)/ca/; \
		fi; \
		cp -pr $$example/ta/*.ta $(OUTPUT_DIR)/ta/; \
	done

prepare-for-rootfs-clean:
	@rm -rf $(OUTPUT_DIR)/ta
	@rm -rf $(OUTPUT_DIR)/ca
	@rmdir --ignore-fail-on-non-empty $(OUTPUT_DIR) || test ! -e $(OUTPUT_DIR)
