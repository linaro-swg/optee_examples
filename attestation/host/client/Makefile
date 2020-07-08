
CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

ROOT ?= ../../../../

BUILDDIR=../../build/
OBJ_DIR=$(BUILDDIR).client/
COMMON_DIR=../common/

OBJ_COMMON = cJSON.o base64.o
OBJS = main.o

BINARY = optee_example_sample_attestation

CFLAGS += -g -Wall -I../../ta/include -I$(TEEC_EXPORT)/include -I./include -I$(COMMON_DIR)
CFLAGS += -I$(ROOT)/out-br/build/libwebsock-3c1615eeadb0b582b63851073bfe3e5132f31ebc/src
CFLAGS += -I$(ROOT)/out-br/build/libevent-2.1.8-stable/include
CFLAGS += -I$(ROOT)/out-br/build/libopenssl-1.1.1a/include


LDADD += -lteec -L$(TEEC_EXPORT)/lib
LDADD +=  $(O_COMMON)
LDADD += -L$(ROOT)/out-br/build/libwebsock-3c1615eeadb0b582b63851073bfe3e5132f31ebc/src/.libs -lwebsock
LDADD += -L$(ROOT)/out-br/build/libopenssl-1.1.1a -levent -levent_pthreads -levent_openssl
LDADD += -L$(ROOT)/out-br/build/libevent-2.1.8-stable/.libs -lssl -lcrypto

O=$(addprefix $(OBJ_DIR), $(OBJS))
O_COMMON=$(addprefix $(OBJ_DIR), $(OBJ_COMMON))

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
