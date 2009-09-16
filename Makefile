
KERNELSRC ?= ../linux
KERNELBUILD ?= ../linux

# default with 'make headers_install'
KERNELHDR ?= $(KERNELSRC)/usr/include

ifneq "$(realpath $(KERNELHDR)/linux/checkpoint.h)" ""
# if .../usr/include contains our headers
CKPT_INCLUDE = -I$(KERNELHDR)
CKPT_HEADERS = $(KERNELHDR)/linux/checkpoint_hdr.h \
	       $(KERNELHDR)/asm/checkpoint_hdr.h
else
# else, usr the kernel source itself
# but first, find linux architecure
KERN_ARCH = $(shell readlink $(KERNELBUILD)/include/asm | sed 's/^asm-//')
CKPT_INCLUDE = -I$(KERNELSRC)/include \
	       -I$(KERNELSRC)/arch/$(KERN_ARCH)/include
CKPT_HEADERS = $(KERNELSRC)/include/linux/checkpoint_hdr.h \
	       $(KERNELSRC)/arch/$(KERN_ARCH)/include/asm/checkpoint_hdr.h
endif

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

PROGS =	self_checkpoint self_restart checkpoint restart ckptinfo

# other cleanup
OTHER = ckptinfo_types.c

LDLIBS = -lm

all: $(PROGS)
	echo $(SUBARCH)
	@make -C test

# restart dependencies
restart: CFLAGS += -D__REENTRANT -pthread

ifneq ($(SUBARCH),)
restart: clone_$(SUBARCH).o
restart: CFLAGS += -DARCH_HAS_CLONE_WITH_PID
endif

# ckptinfo dependencies
ckptinfo: ckptinfo_types.o

ckptinfo_types.c: $(CKPT_HEADERS) ckptinfo.py
	@echo cat $(CKPT_HEADERS) | ./ckptinfo.py > ckptinfo_types.c
	@cat $(CKPT_HEADERS) | ./ckptinfo.py > ckptinfo_types.c

install:
	@echo /usr/bin/install -m 755 checkpoint restart self_restart ckptinfo $(INSTALL_DIR)
	@/usr/bin/install -m 755 checkpoint restart self_restart ckptinfo $(INSTALL_DIR)

clean:
	@rm -f $(PROGS) $(OTHER) *~ *.o
	@make -C test clean
