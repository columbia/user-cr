
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

# compile with debug ?
DEBUG = -DCHECKPOINT_DEBUG

# extra warnings and fun
WARNS := -Wall -Wstrict-prototypes -Wno-trigraphs

# compiler flags
CFLAGS += -g $(WARNS) $(CKPT_INCLUDE) $(DEBUG)

# install dir
INSTALL_DIR = /bin

PROGS =	self ckpt rstr mktree ckptinfo

# other cleanup
OTHER = ckptinfo_types.c

LDLIBS = -lm

all: $(PROGS)
	@make -C test

ckptinfo: ckptinfo_types.o

mktree:	CFLAGS += -D__REENTRANT -pthread

ckptinfo_types.o: ckptinfo_types.c
	@echo $(CC) -c $(CFLAGS) $<
	@$(CC) -c $(CFLAGS) $<

ckptinfo_types.c: $(CKPT_HEADERS) ckptinfo.py
	@echo cat $(CKPT_HEADERS) | ./ckptinfo.py > ckptinfo_types.c
	@cat $(CKPT_HEADERS) | ./ckptinfo.py > ckptinfo_types.c

%.o:	%.c

install:
	@echo /usr/bin/install -m 755 mktree ckpt rstr ckptinfo $(INSTALL_DIR)
	@/usr/bin/install -m 755 mktree ckpt rstr ckptinfo $(INSTALL_DIR)

clean:
	@rm -f $(PROGS) $(OTHER) *~ *.o
	@make -C test clean
