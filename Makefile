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

PROGS =	checkpoint restart ckptinfo

# other cleanup
OTHER = ckptinfo_types.c

LDLIBS = -lm

.PHONY: all distclean clean headers install

all: $(PROGS)
	@make -C test

# restart needs to be thread-safe
restart: CFLAGS += -D__REENTRANT -pthread

# clone_with_pids() is architecture specific
ifneq ($(SUBARCH),)
restart: clone_$(SUBARCH).o
restart: CFLAGS += -DARCH_HAS_CLONE_WITH_PID
endif

# on powerpc, need also assembly file
ifeq ($(SUBARCH),ppc)
restart: clone_$(SUBARCH)_.o
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
