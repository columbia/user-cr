/*
 *  checkpoint.c: checkpoint one or multiple processes
 *
 *  Copyright (C) 2008-2009 Oren Laadan
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <linux/checkpoint.h>

#include "checkpoint.h"
#include "common.h"

static int global_uerrfd = -1;

inline static int checkpoint(pid_t pid, int fd, unsigned long flags, int logfd)
{
	return syscall(__NR_checkpoint, pid, fd, flags, logfd);
}

int cr_checkpoint(int pid, struct cr_checkpoint_args *args)
{
	int ret;

	global_uerrfd = args->uerrfd;

	/* output file descriptor (default: stdout) */
	if (args->outfd < 0)
		args->outfd = STDOUT_FILENO;

	/* output file descriptor (default: none) */
	if (args->logfd < 0)
		args->logfd = CHECKPOINT_FD_NONE;

	if (!args->container)
		args->flags |= CHECKPOINT_SUBTREE;

	ret = checkpoint(pid, args->outfd, args->flags, args->logfd);

	if (ret < 0) {
		ckpt_perror("checkpoint");
		ckpt_err("(you may use 'ckptinfo -e' for more info)\n"); 
	} else if (args->verbose) {
		ckpt_err("checkpoint id %d\n", ret);
	}

	return ret;
}
