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
	int pipe1[2];
	int pipe2[2];
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

	if (pipe(pipe1) < 0 || pipe(pipe2)) {
		perror("pipe");
		exit(1);
	}

	fprintf(file, "hello, world (%.2f)!\n", a);
	fflush(file);

	if (fork() < 0) {
		perror("fork");
		exit(1);
	}

	if (pid == getpid()) {
		close(pipe1[0]);
		write(pipe1[1], &pid, sizeof(pid));
		write(pipe1[1], &pid, sizeof(pid));
		close(pipe2[0]);
	} else {
		close(pipe1[1]);
		close(pipe2[1]);
	}

	for (i = 0; i < 10; i++) {
		sleep(1);
		/* make the fpu work ->  a = a + i/10  */
		a = sqrt(a*a + 2*a*(i/10.0) + i*i/100.0);
		fprintf(file, "[%d] count %d (%.2f)!\n", getpid(), i, a);
		fflush(file);
	}

	if (pid == getpid()) {
		close(pipe1[1]);
		close(pipe2[1]);
	} else {
		ret = read(pipe1[0], &i, sizeof(pid));
		fprintf(file, "[%d] read pid %d (ret %d)\n", pid, i, ret);
		ret = read(pipe1[0], &i, sizeof(pid));
		fprintf(file, "[%d] read pid %d (ret %d)\n", pid, i, ret);
		close(pipe1[0]);
		close(pipe2[0]);
	}
		
	fprintf(file, "[pid %d] world, hello (%.2f) !\n", getpid(), a);
	fflush(file);

	return 0;
}
