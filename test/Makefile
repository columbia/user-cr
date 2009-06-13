
# extra warnings and fun
WARNS := -Wall -Wstrict-prototypes -Wno-trigraphs

# compiler flags
CFLAGS += -g $(WARNS)

TESTS=	onetask multitask bigmem pipes pipes2 shmem \
	ipcshm ipcmsq ipcsem ipcshm_multi zombie

LDLIBS = -lm

all: $(TESTS)

%.o:	%.c

clean:
	@rm -f $(TESTS) *~ *.o
