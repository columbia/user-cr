#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

#define OUTFILE  "/tmp/cr-test.out"

pid_t do_fork(void)
{
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		exit(1);
	}

	return pid;
}

void do_waitpid(FILE *file)
{
	int status;
	pid_t pid;

	pid = waitpid(-1, &status, 0);
	if (pid < 0) {
		fprintf(file, "waitpid failed %d\n", errno);
		fflush(file);
	}

	if (WIFEXITED(status)) {
		fprintf(file, "pid %d exited %d\n", pid, WEXITSTATUS(status));
		fflush(file);
	}

	if (WIFSIGNALED(status)) {
		fprintf(file, "pid %d killed %d\n", pid, WTERMSIG(status));
		fflush(file);
	}
}

int main(int argc, char *argv[])
{
	FILE *file;
	pid_t p1, p2, p3;
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

	p1 = do_fork();
	if (p1 == 0) {
		fprintf(file, "[%d] child exit 0\n", getpid());
		fflush(file);
		exit(0);
	}

	p2 = do_fork();
	if (p2 == 0) {
		fprintf(file, "[%d] child exit 51\n", getpid());
		fflush(file);
		exit(51);
	}

	p3 = do_fork();
	if (p3 == 0) {
		fprintf(file, "[%d] child pausing\n", getpid());
		fflush(file);
		pause();
		exit(2);
	}

	kill(p3, SIGTERM);
		
	for (i = 0; i < 15; i++) {
		fprintf(file, "[%d] count %d\n", getpid(), i);
		fflush(file);
		sleep(1);
		fflush(file);
	}

	do_waitpid(file);
	do_waitpid(file);
	do_waitpid(file);
	
	fprintf(file, "[pid %d] world, hello\n", getpid());
	fflush(file);

	return 0;
}
