# *DOCUMENTATION*
#
# List of environment variables that may be set by caller:
#  KERNELSRC	- path of kernel sources (def: ../linux)
#  SUBARCH	- sub-architecture (def: extract with 'uname')
#  PREFIX	- prefix path for installation (def: /usr/local)
#

KERNELSRC ?= ../linux

CKPT_INCLUDE = -I./include
CKPT_HEADERS = include/linux/checkpoint.h \
		include/linux/checkpoint_hdr.h \
		include/asm/checkpoint_hdr.h

# detect architecture (for eclone)
SUBARCH ?= $(patsubst i%86,x86_32,$(shell uname -m))

# compile with debug ?
DEBUG = -DCHECKPOINT_DEBUG

# extra warnings and fun
WARNS := -Wall -Wstrict-prototypes -Wno-trigraphs

# compiler flags
CFLAGS += -g $(WARNS) $(CKPT_INCLUDE) $(DEBUG)

# install dir
PREFIX ?= /usr/local
BIN_INSTALL_DIR := $(PREFIX)/bin
LIB_INSTALL_DIR := $(PREFIX)/lib

ECLONE_PROGS = restart nsexec
PROGS =	checkpoint ckptinfo $(ECLONE_PROGS)
LIB_ECLONE = libeclone.a

# other cleanup
OTHER = ckptinfo_types.c

LDLIBS = -lm

.PHONY: all distclean clean headers install

all: $(PROGS)
	@$(MAKE) -C test

$(LIB_ECLONE):
	$(AR) ruv $(LIB_ECLONE) $^

# restart needs to be thread-safe
restart: CFLAGS += -D__REENTRANT -pthread

# eclone() is architecture specific
ifneq ($(SUBARCH),)
$(ECLONE_PROGS): $(LIB_ECLONE) 
$(ECLONE_PROGS): CFLAGS += -DARCH_HAS_ECLONE
$(LIB_ECLONE): clone_$(SUBARCH).o genstack.o
endif

# on powerpc, need also assembly file
ifeq ($(SUBARCH),ppc)
CFLAGS += -m32
ASFLAGS += -m32
$(LIB_ECLONE): clone_$(SUBARCH)_.o
endif
ifeq ($(SUBARCH),ppc64)
CFLAGS += -m64
ASFLAGS += -m64
$(LIB_ECLONE): clone_$(SUBARCH)_.o
endif

# ckptinfo dependencies
ckptinfo: ckptinfo_types.o

ckptinfo_types.c: $(CKPT_HEADERS) ckptinfo.py
	cat $(CKPT_HEADERS) | ./ckptinfo.py > ckptinfo_types.c

install: $(PROGS)
	/usr/bin/install -d -D $(BIN_INSTALL_DIR) $(LIB_INSTALL_DIR)
	/usr/bin/install -m 755 checkpoint restart ckptinfo nsexec $(BIN_INSTALL_DIR)
	/usr/bin/install -m 755 $(LIB_ECLONE) $(LIB_INSTALL_DIR)

$(CKPT_HEADERS): %:
	./scripts/extract-headers.sh -s $(KERNELSRC) -o ./include

headers: $(CKPT_HEADERS)

distclean: clean
	@rm -f $(CKPT_HEADERS)

clean:
	@rm -f $(PROGS) $(LIB_ECLONE) $(OTHER) *~ *.o headers.h
	@$(MAKE) -C test clean
