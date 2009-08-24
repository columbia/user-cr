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

int main(int argc, char *argv[])
{
	FILE *file;
	pid_t p1, p2;
	int i;

	close(0);
	close(1);
	close(2);

	setsid();

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
		fprintf(file, "[%d] child born 0\n", getpid());
		fflush(file);
		sleep(1);
		fprintf(file, "[%d] child exit 0\n", getpid());
		exit(0);
	}

	p2 = do_fork();
	if (p2 == 0) {
		fprintf(file, "[%d] child born 1\n", getpid());
		sleep(1);
	} else {
		if (setpgid(p2, p1) < 0) {
			perror("setpgid");
			exit(1);
		}
	}

	for (i = 0; i < 15; i++) {
		fprintf(file, "[%d] count %d\n", getpid(), i);
		fflush(file);
		sleep(1);
		fflush(file);
	}

	fprintf(file, "[pid %d] world, hello\n", getpid());
	fflush(file);

	return 0;
}
