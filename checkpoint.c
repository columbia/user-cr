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
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <linux/checkpoint.h>

static char usage_str[] =
"usage: ckpt [opts] PID\n"
"  'ckpt' takes a checkpoint of the task indicated by PID, and all its\n"
"  descendents, and outputs the checkpoint image. If the task is the\n"
"  init(1) process of a container, it checkpoints the entire container.\n"
"  By default 'ckpt' allows to checkpoint any subtree of tasks. The user\n"
"  can override this feature and request that only whole containers be\n"
"  considered.\n"
"\n"
"\tOptions:\n"
"\t -h,--help             print this help message\n"
"\t -c,--container        require the PID is a container-init\n"
"\t -v,--verbose          verbose output\n"
"";

struct args {
	int container;
	int verbose;
};

static void usage(char *str)
{
	fprintf(stderr, "%s", str);
	exit(1);
}

static void parse_args(struct args *args, int argc, char *argv[])
{
	static struct option opts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "container",	no_argument,		NULL, 'c' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ NULL,		0,			NULL, 0 }
	};
	static char optc[] = "hvc";

	while (1) {
		int c = getopt_long(argc, argv, optc, opts, NULL);
		if (c == -1)
			break;
		switch (c) {
		case '?':
			exit(1);
		case 'h':
			usage(usage_str);
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

	ret = syscall(__NR_checkpoint, pid, STDOUT_FILENO, flags);

	if (ret < 0)
		perror("checkpoint");
	else if (args.verbose)
		fprintf(stderr, "checkpoint id %d\n", ret);

	return (ret > 0 ? 0 : 1);
}
