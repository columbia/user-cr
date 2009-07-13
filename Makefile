
KERNELSRC ?= ../linux
KERNELBUILD ?= ../linux

# compile with debug ?
DEBUG = -DCHECKPOINT_DEBUG

# find linux architecure
KERN_ARCH = $(shell readlink $(KERNELBUILD)/include/asm | sed 's/^asm-//')

# look for includes
PATHS = -I$(KERNELSRC)/include \
	-I$(KERNELSRC)/arch/$(KERN_ARCH)/include

# checkpoint_hdr files
CKPT_HDR = $(KERNELSRC)/include/linux/checkpoint_hdr.h \
	   $(KERNELSRC)/arch/$(KERN_ARCH)/include/asm/checkpoint_hdr.h

# extra warnings and fun
WARNS := -Wall -Wstrict-prototypes -Wno-trigraphs

# compiler flags
CFLAGS += -g $(WARNS) $(PATHS) $(DEBUG)

# install dir
INSTALL_DIR = /bin

PROGS =	self ckpt rstr mktree ckptinfo

# other cleanup
OTHER = ckptinfo_types.c

LDLIBS = -lm

all: $(PROGS)
	@make -C test

ckptinfo: ckptinfo_types.o

ckptinfo_types.o: ckptinfo_types.c
	@echo $(CC) -c $(CFLAGS) $<
	@$(CC) -c $(CFLAGS) $<

ckptinfo_types.c: $(CKPT_HDR) ckptinfo.py
	@echo cat $(CKPT_HDR) | ./ckptinfo.py > ckptinfo_types.c
	@cat $(CKPT_HDR) | ./ckptinfo.py > ckptinfo_types.c

%.o:	%.c

install:
	@echo /usr/bin/install -m 755 mktree ckpt rstr ckptinfo $(INSTALL_DIR)
	@/usr/bin/install -m 755 mktree ckpt rstr ckptinfo $(INSTALL_DIR)

clean:
	@rm -f $(PROGS) $(OTHER) *~ *.o
	@make -C test clean
