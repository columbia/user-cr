#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>

#define OUTFILE  "/tmp/cr-test.out"
#define FIFOFILE  "/tmp/cr-fifo"

int main(int argc, char *argv[])
{
	FILE *file;
	pid_t pid;
	int in, out, inout;
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

	unlink(FIFOFILE);
	if (mkfifo(FIFOFILE, 0644) < 0) {
		perror("mkfifo");
		exit(1);
	}

	inout = open(FIFOFILE, O_RDWR, 0);
	if (inout < 0 ) {
		perror("open inout");
		exit(1);
	}

	in = open(FIFOFILE, O_RDONLY, 0);
	if (in < 0 ) {
		perror("open in");
		exit(1);
	}

	out = open(FIFOFILE, O_WRONLY, 0);
	if (out < 0 ) {
		perror("open out");
		exit(1);
	}

	fprintf(file, "hello, world\n");
	fflush(file);

	ret = write(out, &pid, sizeof(pid));
	fprintf(file, "[%d] write(1) pid %d (ret %d)\n", pid, i, ret);
	fflush(file);

	for (i = 0; i < 10; i++) {
		sleep(1);
		fprintf(file, "[%d] count %d\n", getpid(), i);
		fflush(file);
	}

	fprintf(file, "[pid %d] world, hello\n", getpid());
	fflush(file);

	ret = read(in, &i, sizeof(pid));
	fprintf(file, "[%d] read(1) pid %d (ret %d)\n", pid, i, ret);
	fflush(file);

	ret = write(inout, &pid, sizeof(pid));
	fprintf(file, "[%d] write(2) pid %d (ret %d)\n", pid, i, ret);
	fflush(file);

	ret = read(inout, &i, sizeof(pid));
	fprintf(file, "[%d] read(2) pid %d (ret %d)\n", pid, i, ret);
	fflush(file);

	close(inout);
	close(out);
	close(in);

	fprintf(file, "[pid %d] world, hello\n", getpid());
	fflush(file);

	return 0;
}
