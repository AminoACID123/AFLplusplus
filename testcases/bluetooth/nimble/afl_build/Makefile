CC := afl-clang-lto
CXX := afl-clang-lto++
LD := afl-clang-lto
SIZE    := size

# Configure NimBLE variables
NIMBLE_ROOT := /home/xaz/Documents/lightblue/mynewt-nimble
BUILDDIR := ${CURDIR}
NIMBLE_CFG_TINYCRYPT := 1


# Skip files that don't build for this port
NIMBLE_IGNORE := $(NIMBLE_ROOT)/porting/nimble/src/hal_timer.c \
	$(NIMBLE_ROOT)/porting/nimble/src/os_cputime.c \
	$(NIMBLE_ROOT)/porting/nimble/src/os_cputime_pwr2.c \
	$(wildcard $(NIMBLE_ROOT)/nimble/transport/socket/src/*.c) \
	$(NULL)

include $(NIMBLE_ROOT)/porting/nimble/Makefile.defs

SRC := $(NIMBLE_SRC)

# Source files for NPL OSAL
SRC += \
	$(wildcard $(NIMBLE_ROOT)/porting/npl/linux/src/*.c) \
	$(wildcard $(NIMBLE_ROOT)/porting/npl/linux/src/*.cc) \
	$(TINYCRYPT_SRC) \
	$(NULL)


# Add NPL and all NimBLE directories to include paths
INC = \
    ./include \
	$(NIMBLE_ROOT)/porting/npl/linux/include \
	$(NIMBLE_INCLUDE) \
	$(TINYCRYPT_INCLUDE) \
	$(NULL)

INCLUDES := $(addprefix -I, $(INC))

SRC_C  = $(filter %.c,  $(SRC))
SRC_CC = $(filter %.cc, $(SRC))

OBJ := $(patsubst $(NIMBLE_ROOT)/%, $(BUILDDIR)/%,  $(SRC_C:.c=.o)) 
OBJ += $(patsubst $(NIMBLE_ROOT)/%, $(BUILDDIR)/%,  $(SRC_CC:.cc=.o))

TINYCRYPT_OBJ := $(patsubst $(NIMBLE_ROOT)/%, $(BUILDDIR)/%,  $(TINYCRYPT_SRC:.c=.o))  
CFLAGS =                    \
    $(NIMBLE_CFLAGS)        \
    $(INCLUDES)             \
    -g                      \
    -D_GNU_SOURCE           \
    $(NULL)

LIBS := $(NIMBLE_LDFLAGS) -lrt -lpthread -lstdc++

.PHONY: all clean
.DEFAULT: all

all: nimble-linux

clean:
	rm $(OBJ) -f
	rm -f main.o
	rm -f hci_transport_fuzz.o
	rm nimble-linux -f

$(TINYCRYPT_OBJ): CFLAGS+=$(TINYCRYPT_CFLAGS)

main.o: ../main.c
	$(CC) -c $(INCLUDES) $(CFLAGS) -o $@ $<

hci_transport_fuzz.o: ../hci_transport_fuzz.c
	$(CC) -c $(INCLUDES) $(CFLAGS) -o $@ $<

${BUILDDIR}/%.o: $(NIMBLE_ROOT)/%.c
	mkdir -p $(@D)
	$(CC) -c $(INCLUDES) $(CFLAGS) -o $@ $<

${BUILDDIR}/%.o: $(NIMBLE_ROOT)/%.cc
	mkdir -p $(@D)
	$(CXX) -c $(INCLUDES) $(CFLAGS) -o $@ $<

nimble-linux: main.o hci_transport_fuzz.o $(OBJ) $(TINYCRYPT_OBJ)
	$(LD) -o $@ $^ $(LIBS)
	$(SIZE) $@
