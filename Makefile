KERNELSRC ?= ../linux

CKPT_INCLUDE = -I./include
CKPT_HEADERS = include/linux/checkpoint.h \
		include/linux/checkpoint_hdr.h \
		include/asm/checkpoint_hdr.h

# detect architecture (for clone_with_pids)
SUBARCH = $(patsubst i%86,x86_32,$(shell uname -m))

# compile with debug ?
DEBUG = -DCHECKPOINT_DEBUG

# extra warnings and fun
WARNS := -Wall -Wstrict-prototypes -Wno-trigraphs

# compiler flags
CFLAGS += -g $(WARNS) $(CKPT_INCLUDE) $(DEBUG)

# install dir
INSTALL_DIR = /bin

PROGS =	checkpoint restart ckptinfo nsexeccwp

# other cleanup
OTHER = ckptinfo_types.c

LDLIBS = -lm

.PHONY: all distclean clean headers install

all: $(PROGS)
	@make -C test

# restart needs to be thread-safe
restart: CFLAGS += -D__REENTRANT -pthread

# eclone() is architecture specific
ifneq ($(SUBARCH),)
restart: clone_$(SUBARCH).o genstack.o
restart: CFLAGS += -DARCH_HAS_ECLONE
nsexeccwp: clone_$(SUBARCH).o
nsexeccwp: CFLAGS += -DARCH_HAS_ECLONE
endif

# on powerpc, need also assembly file
ifeq ($(SUBARCH),ppc)
restart: clone_$(SUBARCH)_.o
nsexeccwp: clone_$(SUBARCH)_.o
endif

# ckptinfo dependencies
ckptinfo: ckptinfo_types.o

ckptinfo_types.c: $(CKPT_HEADERS) ckptinfo.py
	cat $(CKPT_HEADERS) | ./ckptinfo.py > ckptinfo_types.c

install:
	@echo /usr/bin/install -m 755 checkpoint restart ckptinfo $(INSTALL_DIR)
	@/usr/bin/install -m 755 checkpoint restart ckptinfo $(INSTALL_DIR)

$(CKPT_HEADERS): %:
	./scripts/extract-headers.sh -s $(KERNELSRC) -o ./include

headers: $(CKPT_HEADERS)

distclean: clean
	@rm -f $(CKPT_HEADERS)

clean:
	@rm -f $(PROGS) $(OTHER) *~ *.o headers.h
	@make -C test clean
