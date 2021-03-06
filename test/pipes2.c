#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#define OUTFILE  "/tmp/cr-test.out"

int main(int argc, char *argv[])
{
	FILE *file;
	float a;
	pid_t pid;
	int pipefd[2];
	int i, ret;

	pid = getpid();

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

	if (pipe(pipefd) < 0) {
		perror("pipe");
		exit(1);
	}

	fprintf(file, "hello, world (%.2f)!\n", a);
	fflush(file);

	ret = write(pipefd[1], &pid, sizeof(pid));
	fprintf(file, "[%d] write(1) pid %d (ret %d)\n", pid, i, ret);
	fflush(file);

	for (i = 0; i < 10; i++) {
		sleep(1);
		/* make the fpu work ->  a = a + i/10  */
		a = sqrt(a*a + 2*a*(i/10.0) + i*i/100.0);
		fprintf(file, "[%d] count %d (%.2f)!\n", getpid(), i, a);
		fflush(file);
	}

	fprintf(file, "[pid %d] world, hello (%.2f) !\n", getpid(), a);
	fflush(file);

	ret = read(pipefd[0], &i, sizeof(pid));
	fprintf(file, "[%d] read(1) pid %d (ret %d)\n", pid, i, ret);
	fflush(file);

	ret = write(pipefd[1], &pid, sizeof(pid));
	fprintf(file, "[%d] write(2) pid %d (ret %d)\n", pid, i, ret);
	fflush(file);

	ret = read(pipefd[0], &i, sizeof(pid));
	fprintf(file, "[%d] read(2) pid %d (ret %d)\n", pid, i, ret);
	fflush(file);

	close(pipefd[1]);
	close(pipefd[0]);

	fprintf(file, "[pid %d] world, hello (%.2f) !\n", getpid(), a);
	fflush(file);

	return 0;
}
