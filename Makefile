
# compile with debug ?
DEBUG = -DCHECKPOINT_DEBUG

# find linux architecure
KERN_ARCH = $(shell readlink ../linux/include/asm | sed 's/^asm-//')

# look for includes
PATHS = -I../linux/include \
	-I../linux/arch/$(KERN_ARCH)/include

# extra warnings and fun
WARNS := -Wall -Wstrict-prototypes -Wno-trigraphs

# compiler flags
CFLAGS += -g $(WARNS) $(PATHS) $(DEBUG)

PROGS =	self ckpt rstr mktree
TESTS=	test1 test2

LDLIBS = -lm

all: $(PROGS) $(TESTS)

mktree:	mktree.o
self:	self.o
ckpt:	ckpt.o
rstr:	rstr.o

test1:	test1.c
test2:	test2.c

clean:
	@rm -f $(PROGS) $(TESTS) *~ *.o
