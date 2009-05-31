/*
 *  self.c: demonstrate self-checkpoint
 *
 *  Copyright (C) 2008 Oren Laadan
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>
#include <sys/syscall.h>

#include <linux/checkpoint_types.h>

#define OUTFILE  "/tmp/cr-self.out"

int main(int argc, char *argv[])
{
	pid_t pid = getpid();
	FILE *file;
	int i, ret;
	float a;

	close(0);
	close(2);

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

	fprintf(file, "hello, world (%.2f)!\n", a);
	fflush(file);

	for (i = 0; i < 1000; i++) {
		sleep(1);
		/* make the fpu work ->  a = a + i/10  */
		a = sqrt(a*a + 2*a*(i/10.0) + i*i/100.0);
		fprintf(file, "count %d (%.2f)!\n", i, a);
		fflush(file);

		if (i == 2) {
			ret = syscall(__NR_checkpoint,
				      pid, STDOUT_FILENO, CHECKPOINT_SUBTREE);
			if (ret < 0) {
				fprintf(file, "ckpt: %s\n", strerror(errno));
				exit(2);
			}
			fprintf(file, "checkpoint ret: %d\n", ret);
			fflush(file);
		}
	}
		
	return 0;
}
