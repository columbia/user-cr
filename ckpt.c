/*
 *  ckpt.c: checkpoint one or multiple processes
 *
 *  Copyright (C) 2008 Oren Laadan
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(int argc, char *argv[])
{
	pid_t pid;
	int ret;

	if (argc != 2) {
		printf("usage: ckpt PID\n");
		exit(1);
	}

	pid = atoi(argv[1]);
	if (pid <= 0) {
		printf("invalid pid\n");
		exit(1);
	}

	ret = syscall(__NR_checkpoint, pid, STDOUT_FILENO, 0);

	if (ret < 0)
		perror("checkpoint");
	else
		printf("checkpoint id %d\n", ret);

	return (ret > 0 ? 0 : 1);
}
