PLUGIN_UUID = 96bcf744-4f72-4866-bf1d-8634fd9c65e5

PLUGIN			= $(PLUGIN_UUID).plugin
PLUGIN_SRS		= $(wildcard ./*.c)
PLUGIN_OBJ		= $(patsubst %.c, %.o, $(PLUGIN_SRS))
PLUGIN_INCLUDES_DIR	= $(CURDIR) $(TEEC_EXPORT)/include

PLUGIN_INCLUDES		= $(addprefix -I, $(PLUGIN_INCLUDES_DIR))
PLUGIN_CCFLAGS		= -Wall -fPIC
PLUGIN_LDFLAGS		= -shared

.PHONY: all
all: $(PLUGIN)

$(PLUGIN): $(PLUGIN_OBJ)
	$(CROSS_COMPILE)gcc $(PLUGIN_LDFLAGS) $(PLUGIN_OBJ) -o $@

%.o: %.c
	$(CROSS_COMPILE)gcc $(PLUGIN_CCFLAGS) $(PLUGIN_INCLUDES) -c $*.c -o $*.o

.PHONY: clean
clean:
	$(RM) $(PLUGIN_OBJ) $(PLUGIN_UUID).plugin

