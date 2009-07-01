#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#define OUTFILE  "/tmp/cr-test.out"

FILE *file;

void handler(int sig)
{
	fprintf(file, "received signal %d\n", sig);
}

int main(int argc, char *argv[])
{
	sigset_t set;
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

	fprintf(file, "hello, world\n");
	fflush(file);

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigprocmask(SIG_BLOCK, &set, NULL);

	signal(SIGUSR1, handler);
	signal(SIGUSR2, handler);

	kill(getpid(), SIGUSR1);
	kill(getpid(), SIGUSR2);

	for (i = 0; i < 15; i++) {
		fprintf(file, "[%d] count %d\n", getpid(), i);
		fflush(file);
		sleep(1);
		fflush(file);
	}

	sigprocmask(SIG_UNBLOCK, &set, NULL);

	fprintf(file, "world, hello\n");
	fflush(file);

	return 0;
}
