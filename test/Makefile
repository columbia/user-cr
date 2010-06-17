# handle cross-compilation
AR  := ${CROSS_COMPILE}ar
AS  := ${CROSS_COMPILE}as
CC  := ${CROSS_COMPILE}gcc
CPP := ${CROSS_COMPILE}cpp
LD  := ${CROSS_COMPILE}ld

# extra warnings and fun
WARNS := -Wall -Wstrict-prototypes -Wno-trigraphs

# compiler flags
CFLAGS += -g $(WARNS)

TESTS=	onetask multitask bigmem pipes pipes2 fifo shmem \
	ipcshm ipcmsq ipcsem ipcshm_multi zombie sigpending \
	itimer pty pgrp

LDLIBS = -lm

all: $(TESTS)

%.o:	%.c

pty:	LDLIBS = -lutil

clean:
	@rm -f $(TESTS) *~ *.o
