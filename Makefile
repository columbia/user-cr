
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

PROGS =	self ckpt rstr mktree ckptinfo

LDLIBS = -lm

all: $(PROGS)
	@make -C test

%.o:	%.c

clean:
	@rm -f $(PROGS) *~ *.o
	@make -C test clean
