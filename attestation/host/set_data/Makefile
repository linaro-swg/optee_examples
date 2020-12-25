CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

BUILDDIR=../../build/
OBJ_DIR=$(BUILDDIR).set_data/
COMMON_DIR=../common/

OBJ_COMMON = cJSON.o base64.o
OBJS = main.o

O=$(addprefix $(OBJ_DIR), $(OBJS))
O_COMMON=$(addprefix $(OBJ_DIR), $(OBJ_COMMON))

CFLAGS += -Wall -I$(TEEC_EXPORT)/include -I./include -I$(COMMON_DIR)

LDADD += -lteec -L$(TEEC_EXPORT)/lib $(O_COMMON)

BINARY = optee_example_set_data

.PHONY: all
all: $(BINARY)

$(BINARY): $(O) $(O_COMMON) | $(BUILDDIR)
	$(CC) -o $(BUILDDIR)$@ $< $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJ_DIR)* $(BUILDDIR)$(BINARY)

$(OBJ_DIR)%.o: %.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)%.o: $(COMMON_DIR)%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR) $(OBJ_DIR):
	mkdir -p $@
