#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>

#define OUTFILE  "/tmp/cr-test.out"

FILE *file;

int sigcount;

void handler(int sig)
{
	fprintf(file, "[%d] received signal %d\n", sigcount, sig);
	fflush(file);
	if (sigcount++ == 20) {
		fprintf(file, "world, hello\n");
		fflush(file);
		exit(0);
	}
}

int main(int argc, char *argv[])
{
	struct itimerval itimer;

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

	signal(SIGALRM, handler);
	signal(SIGVTALRM, handler);

	itimer.it_value.tv_sec = 1;
	itimer.it_value.tv_usec = 0;
	itimer.it_interval.tv_sec = 1;
	itimer.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &itimer, NULL);

	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = 350;
	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = 350;
	setitimer(ITIMER_VIRTUAL, &itimer, NULL);

	while (1) { }

	return 0;
}
