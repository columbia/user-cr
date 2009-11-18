#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <sys/mman.h>

#define OUTFILE  "/tmp/cr-test.out"

int main(int argc, char *argv[])
{
	FILE *file;
	int *addr;
	float a = 0;
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

	if (pipe(pipefd) < 0) {
		perror("pipe");
		exit(1);
	}

	addr = mmap(NULL, 16384, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_SHARED, 0, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	addr[8192/sizeof(int)] = 100;
	addr[4196/sizeof(int)] = 200;

	fprintf(file, "hello, world (%.2f)!\n", a);
	fflush(file);

	if (fork() < 0) {
		perror("fork");
		exit(1);
	}

	if (pid == getpid()) {
		close(pipefd[0]);
		write(pipefd[1], &pid, sizeof(pid));
		write(pipefd[1], &pid, sizeof(pid));
	} else {
		close(pipefd[1]);
	}

	for (i = 0; i < 10; i++) {
		sleep(1);
		/* make the fpu work ->  a = a + i/10  */
		a = sqrt(a*a + 2*a*(i/10.0) + i*i/100.0);
		/* touch and modify shared memory */
		addr[8192/sizeof(int)]++;
		fprintf(file, "[%d] count %d (%.2f) mem %d!\n",
			getpid(), i, a, addr[8192/sizeof(int)]);
		fflush(file);
	}

	if (pid == getpid()) {
		close(pipefd[1]);
	} else {
		ret = read(pipefd[0], &i, sizeof(pid));
		fprintf(file, "[%d] read pid %d (ret %d)\n", pid, i, ret);
		ret = read(pipefd[0], &i, sizeof(pid));
		fprintf(file, "[%d] read pid %d (ret %d)\n", pid, i, ret);
		close(pipefd[0]);
	}

	addr[8192/sizeof(int)]++;
	fprintf(file, "[pid %d] shmem %d\n", getpid(), addr[8192/sizeof(int)]);
		
	fprintf(file, "[pid %d] world, hello (%.2f) !\n", getpid(), a);
	fflush(file);

	return 0;
}
