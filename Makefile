
# compile with debug ?
DEBUG = -DCHECKPOINT_DEBUG

# look for includes
PATHS = -I../linux-2.6-orenl/include

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
