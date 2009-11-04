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
#include <fcntl.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <linux/checkpoint.h>

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
"  -c,--container        require the PID is a container-init\n"
"  -v,--verbose          verbose output\n"
"";

struct args {
	char *output;
	int outfd;
	char *logfile;
	int logfd;
	int container;
	int verbose;
};

inline static int checkpoint(pid_t pid, int fd, unsigned long flags, int logfd)
{
	return syscall(__NR_checkpoint, pid, fd, flags, logfd);
}

static void usage(char *str)
{
	fprintf(stderr, "%s", str);
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

static void parse_args(struct args *args, int argc, char *argv[])
{
	static struct option opts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "output",	required_argument,	NULL, 'o' },
		{ "output-fd",	required_argument,	NULL, 1 },
		{ "logfile",	required_argument,	NULL, 'l' },
		{ "logfile-fd",	required_argument,	NULL, 2 },
		{ "container",	no_argument,		NULL, 'c' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ NULL,		0,			NULL, 0 }
	};
	static char optc[] = "hvco:l:";

	/* defaults */
	args->outfd = -1;
	args->logfd = -1;

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
			args->output = optarg;
			break;
		case 1:
			args->outfd = str2num(optarg);
			if (args->outfd < 0) {
				printf("checkpoint: invalid file descriptor\n");
				exit(1);
			}
			break;
		case 'l':
			args->logfile = optarg;
			break;
		case 2:
			args->logfd = str2num(optarg);
			if (args->logfd < 0) {
				printf("checkpoint: invalid file descriptor\n");
				exit(1);
			}
			break;
		case 'c':
			args->container = 1;
			break;
		case 'v':
			args->verbose = 1;
			break;
		default:
			usage(usage_str);
		}
	}

	if (args->output && args->outfd >= 0) {
		printf("Invalid used of both -o/--output and --output-fd\n");
		exit(1);
	}
	if (args->logfile && args->logfd >= 0) {
		printf("Invalid used of both -l/--logfile and --logfile-fd\n");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	struct args args;
	unsigned long flags = 0;
	pid_t pid;
	int ret;

	memset(&args, 0, sizeof(args));
	parse_args(&args, argc, argv);

	argc -= optind;
	if (argc != 1)
		usage(usage_str);

	if (!args.container)
		flags |= CHECKPOINT_SUBTREE;

	pid = atoi(argv[optind]);
	if (pid <= 0) {
		printf("invalid pid\n");
		exit(1);
	}

	/* output file */
	if (args.output) {
		args.outfd = open(args.output,
				     O_RDWR | O_CREAT | O_EXCL, 0644);
		if (args.outfd < 0) {
			perror("open output file");
			exit(1);
		}
	}

	/* output file descriptor (default: stdout) */
	if (args.outfd < 0)
		args.outfd = STDOUT_FILENO;

	/* (optional) log file */
	if (args.logfile) {
		args.logfd = open(args.logfile,
				  O_RDWR | O_CREAT | O_EXCL, 0644);
		if (args.logfd < 0) {
			perror("open log file");
			exit(1);
		}
	}

	/* output file descriptor (default: none) */
	if (args.logfd < 0)
		args.logfd = CHECKPOINT_FD_NONE;

	ret = checkpoint(pid, args.outfd, flags, args.logfd);

	if (ret < 0) {
		perror("checkpoint");
		fprintf(stderr, "(you may use 'ckptinfo -e' for more info)\n"); 
	} else if (args.verbose) {
		fprintf(stderr, "checkpoint id %d\n", ret);
	}

	return (ret > 0 ? 0 : 1);
}
