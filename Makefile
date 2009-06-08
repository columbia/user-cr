
KERNELPATH ?= ../linux

# compile with debug ?
DEBUG = -DCHECKPOINT_DEBUG

# find linux architecure
KERN_ARCH = $(shell readlink $(KERNELPATH)/include/asm | sed 's/^asm-//')

# look for includes
PATHS = -I$(KERNELPATH)/include \
	-I$(KERNELPATH)/arch/$(KERN_ARCH)/include

# extra warnings and fun
WARNS := -Wall -Wstrict-prototypes -Wno-trigraphs

# compiler flags
CFLAGS += -g $(WARNS) $(PATHS) $(DEBUG)

# install dir
INSTALL_DIR = /bin

PROGS =	self ckpt rstr mktree ckptinfo

LDLIBS = -lm

all: $(PROGS)
	@make -C test

%.o:	%.c

install:
	@echo /usr/bin/install -m 755 mktree ckpt rstr ckptinfo $(INSTALL_DIR)
	@/usr/bin/install -m 755 mktree ckpt rstr ckptinfo $(INSTALL_DIR)

clean:
	@rm -f $(PROGS) *~ *.o
	@make -C test clean
