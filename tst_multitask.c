#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#define OUTFILE  "/tmp/cr-test.out"

int do_deep_fork(int depth, int breadth)
{
	int i;

	for (i = 0; i < breadth; i++) {
		switch (fork()) {
		case -1:
			perror("fork");
			return -1;
		case 0:
			return do_deep_fork(depth-1, breadth-1);
		default:
			break;
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	FILE *file;
	float a;
	int i;

	close(0);
	close(1);
	close(2);

	setpgrp();

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

	a = sqrt(2.53 * (getpid() / 1.21));

	fprintf(file, "hello, world (%.2f)!\n", a);
	fflush(file);

	if (do_deep_fork(2, 2) < 0)
		exit(1);
		
	for (i = 0; i < 1000; i++) {
		sleep(1);
		/* make the fpu work ->  a = a + i/10  */
		a = sqrt(a*a + 2*a*(i/10.0) + i*i/100.0);
		fprintf(file, "[%d] count %d (%.2f)!\n", getpid(), i, a);
		fflush(file);
	}
		
	fprintf(file, "[pid %d] world, hello (%.2f) !\n", getpid(), a);
	fflush(file);

	return 0;
}
