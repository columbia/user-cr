
#define _XOPEN_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pty.h>

#define OUTFILE  "/tmp/cr-test.out"

FILE *file;

int open_pty_1(int ptys[2])
{
	int master, slave;
	char *slavename;

	if ((master = open("/dev/ptmx", O_RDWR | O_NOCTTY)) < 0) {
		perror("open master");
		return -1;
	}

	if (grantpt(master) < 0) {
		perror("grantpt");
		return -1;
	}

	if (unlockpt(master) < 0) {
		perror("unlockpt");
		return -1;
	}

	if (!(slavename = ptsname(master))) {
		perror("ptsname");
		return -1;
	}

	fprintf(file, "slave#1: %s\n", slavename);
	fflush(file);

	if ((slave = open(slavename, O_RDWR | O_NOCTTY)) < 0) {
		perror("open slave");
		return -1;
	}

	ptys[0] = master;
	ptys[1] = slave;

	return 0;
}

int open_pty_2(int ptys[2])
{
	char slavename[128];

	if (openpty(&ptys[0], &ptys[1], slavename, NULL, NULL) < 0) {
		perror("openpty");
		return -1;
	}

	fprintf(file, "slave#2: %s\n", slavename);
	fflush(file);

	return 0;
}



int main(int argc, char *argv[])
{
	int pty_1[2], pty_2[2];
	char str[16], t1[16], t2[16];
	pid_t pid = getpid();
	int i, ret;

	memset(t1, 0, 16);
	memset(t2, 0, 16);

	close(0);
	close(1);
	close(2);

	setpgid(0, 0);

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

	if (open_pty_1(pty_1) < 0)
		exit(1);
	if (open_pty_1(pty_2) < 0)
		exit(1);
#if _not_yet_
	if (open_pty_2(pty_2) < 0)
		exit(1);
#endif

	sprintf(str, "pid=%d\n", pid);
	if (write(pty_1[0], str, strlen(str)) < 0) {
		perror("write 1");
		exit(1);
	}
	if (write(pty_2[1], str, strlen(str)) < 0) {
		perror("write 2");
		exit(1);
	}

	close(pty_2[1]);
	
	for (i = 0; i < 15; i++) {
		fprintf(file, "[%d] count %d\n", getpid(), i);
		fflush(file);
		sleep(1);
	}
	
	fprintf(file, "\n1st result:\n");
	fflush(file);
	ret = read(pty_1[1], t1, strlen(str));
	fprintf(file, "[%d] read(1) str %s (ret %d, errno %d)\n",
		pid, t1, ret, errno);
	fflush(file);

	fprintf(file, "\n2st result:\n");
	fflush(file);
	ret = read(pty_2[0], t2, strlen(str));
	fprintf(file, "[%d] read(1) str %s\n (ret %d, errno %d)\n",
		pid, t2, ret, errno);
	fflush(file);

	return 0;
}
