/*
 *  checkpoint-main.c: checkpoint one or multiple processes
 *
 *  Copyright (C) 2008-2011 Oren Laadan
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>

#include <linux/checkpoint.h>

#include "checkpoint.h"
#include "common.h"

static int global_uerrfd = -1;

static char usage_str[] =
"usage: ckpt [opts] PID\n"
"  'checkpoint' takes a checkpoint of the task indicated by PID, and all\n"
"  its descendents, and outputs the checkpoint image. If the task is the\n"
"  init(1) process of a container, it checkpoints the entire container.\n"
"  By default 'checkpoint' allows to checkpoint any subtree of tasks. The\n"
"  user can override this feature and request that only whole containers\n"
"  be considered.\n"
"\n"
"\tOptions:\n"
"  -h,--help             print this help message\n"
"  -o,--output=FILE      write data to FILE instead of standard output\n"
"     --output-fd=FD     write data to file descriptor FD instead of stdout\n"
"  -l,--logfile=FILE     write error and debug data to FILE (default=none)\n"
"     --logile-fd=FD     write error and debug data to file descriptor FD\n"
"  -f,--force            if an output file already exists, overwrite it\n"
"  -c,--container        require the PID is a container-init\n"
"  -N,--netns            checkpoint network namespace(s)\n"
"  -v,--verbose          verbose output\n"
"";

static void usage(char *str)
{
	ckpt_err("%s", str);
	exit(1);
}

/* negative retval means error */
static int str2num(char *str)
{
	char *nptr;
	int num;

	num = strtol(str, &nptr, 10);
	if (nptr - str != strlen(str))
		num = -1;
	return num;
}

static void parse_args(struct cr_checkpoint_args *args, int argc, char *argv[])
{
	static struct option opts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "output",	required_argument,	NULL, 'o' },
		{ "output-fd",	required_argument,	NULL, 1 },
		{ "logfile",	required_argument,	NULL, 'l' },
		{ "logfile-fd",	required_argument,	NULL, 2 },
		{ "force",	no_argument,		NULL, 'f' },
		{ "container",	no_argument,		NULL, 'c' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ "netns",	no_argument,		NULL, 'N' },
		{ NULL,		0,			NULL, 0 }
	};
	static char optc[] = "hvcfo:l:N";
	char *output;
	char *logfile;
	int outfd;
	int logfd;
	int force;
	int excl;

	/* defaults */
	args->outfd = fileno(stdout);
	args->logfd = CHECKPOINT_FD_NONE;
	args->uerrfd = fileno(stderr);

	output = NULL;
	logfile = NULL;
	outfd = -1;
	logfd = -1;
	force = 0;

	while (1) {
		int c = getopt_long(argc, argv, optc, opts, NULL);
		if (c == -1)
			break;
		switch (c) {
		case '?':
			exit(1);
		case 'h':
			usage(usage_str);
		case 'o':
			output = optarg;
			break;
		case 1:
			outfd = str2num(optarg);
			if (outfd < 0) {
				ckpt_err("checkpoint: invalid file descriptor\n");
				exit(1);
			}
			break;
		case 'l':
			logfile = optarg;
			break;
		case 2:
			logfd = str2num(optarg);
			if (logfd < 0) {
				ckpt_err("checkpoint: invalid file descriptor\n");
				exit(1);
			}
			break;
		case 'c':
			args->container = 1;
			break;
		case 'v':
			args->verbose = 1;
			break;
		case 'N':
			args->flags |= CHECKPOINT_NETNS;
			break;
		default:
			usage(usage_str);
		}
	}

	if (output && outfd >= 0) {
		ckpt_err("Invalid use of both -o/--output and --output-fd\n");
		exit(1);
	}

	excl = force ? 0 : O_EXCL;

	/* output file */
	if (output) {
		args->outfd = open(output, O_RDWR | O_CREAT | excl, 0644);
		if (args->outfd < 0) {
			ckpt_perror("open output file");
			exit(1);
		}
	} else if (outfd >= 0)
		args->outfd = outfd;

	if (logfile && logfd >= 0) {
		ckpt_err("Invalid use of both -l/--logfile and --logfile-fd\n");
		exit(1);
	}

	/* (optional) log file */
	if (logfile) {
		args->logfd = open(logfile, O_RDWR | O_CREAT | excl, 0644);
		if (args->logfd < 0) {
			ckpt_perror("open log file");
			exit(1);
		}
	} else if (logfd >= 0)
		args->logfd = logfd;
}

int main(int argc, char *argv[])
{
	int ret;
	struct cr_checkpoint_args args;
	pid_t pid;

	global_uerrfd = fileno(stderr);

	memset(&args, 0, sizeof(args));
	parse_args(&args, argc, argv);

	argc -= optind;
	if (argc != 1)
		usage(usage_str);

	pid = atoi(argv[optind]);
	if (pid <= 0) {
		ckpt_err("invalid pid\n");
		exit(1);
	}

	ret = cr_checkpoint(pid, &args);

	return (ret > 0) ? 0 : 1;
}
