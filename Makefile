
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

PROGS =	self ckpt rstr mktree
TESTS=	test1 test2 test3 test4

LDLIBS = -lm

all: $(PROGS) $(TESTS)

mktree:	mktree.o
self:	self.o
ckpt:	ckpt.o
rstr:	rstr.o

test1:	test1.c
test2:	test2.c
test3:	test3.c
test4:	test4.c

clean:
	@rm -f $(PROGS) $(TESTS) *~ *.o
