
# compile with debug ?
DEBUG = -DCHECKPOINT_DEBUG

# look for includes
PATHS = -I../linux-2.6-orenl/include

# extra warnings and fun
WARNS := -Wall -Wstrict-prototypes -Wno-trigraphs

# compiler flags
CFLAGS += -g $(WARNS) $(PATHS) $(DEBUG)

PROGS =	mktree

mktree:	mktree.o


