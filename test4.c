#define _GNU_SOURCE        /* or _BSD_SOURCE or _SVID_SOURCE */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <asm/unistd.h>
#include <sys/syscall.h>

#define OUTFILE  "/tmp/cr-test.out"

int main(int argc, char *argv[])
{
	pid_t pid = getpid();
	FILE *file;
	float a, b;
	int ret;

	close(0);
	close(2);

	unlink(OUTFILE);
	file = fopen(OUTFILE, "w+");
	if (!file) {
		perror("open");
		exit(1);
	}

	if (dup2(0,2) < 0) {
		perror("dup2");
		exit(1);
	}

	a = 2.53;
	b = a * (getpid() / 1.21);
	a = sqrt(b);

	fprintf(file, "hello, world (%.2f %.2f)!\n", a, b);
	fflush(file);

	ret = syscall(__NR_checkpoint, pid, STDOUT_FILENO, 0);
	if (ret < 0) {
		fprintf(file, "checkpoint: %s\n", strerror(errno));
		exit(2);
	}

	b = a * a * b;
	a = sqrt(b);

	fprintf(file, "world, hello (%.2f) !\n", a);
	fprintf(file, "(ret = %d)\n", ret);
	fflush(file);

	while (1)
		;

	return 0;
}
