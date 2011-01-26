/*
 *  restart-main.c: restart process(es) from a checkpoint
 *
 *  Copyright (C) 2008-2011 Oren Laadan
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <limits.h>
#include <getopt.h>

#include "checkpoint.h"
#include "common.h"

static int global_ulogfd;
static int global_uerrfd;
static int global_debug;
static int global_verbose;
static struct signal_array signal_array[] = INIT_SIGNAL_ARRAY;

static char usage_str[] =
"usage: restart [opts]\n"
"  restart restores from a checkpoint image by first creating in userspace\n"
"  the original tasks tree, and then calling sys_restart by each task.\n"
"Options:\n"
"  -h,--help             print this help message\n"
"  -p,--pidns            create a new pid namspace (default with --pids)\n"
"  -P,--no-pidns         do not create a new pid namespace (default)\n"
"     --pids             restore original pids (default with --pidns)\n"
"     --self             restart a single task, usually from self-checkpoint\n"
"  -r,--root=ROOT        restart under the directory ROOT instead of current\n"
"     --signal=SIG       send SIG to root task on SIGINT (default: SIGKILL\n"
"                        to container root, SIGINT otherwise)\n"
"     --mntns            restart under a private mounts namespace\n"
"     --mount-pty        start in a new devpts namespace to supprt ptys\n"
"  -w,--wait             wait for root task to termiate (default)\n"
"     --show-status      show exit status of root task (implies -w)\n"
"     --copy-status      imitate exit status of root task (implies -w)\n"
"  -W,--no-wait          do not wait for root task to terminate\n"
"  -k,--keeplsm          try to recreate original LSM labels on all objects\n"
"  -F,--freezer=CGROUP   freeze tasks in freezer group CGROUP on success\n"
"  -i,--input=FILE       read data from FILE instead of standard input\n"
"     --input-fd=FD      read data from file descriptor FD (instead of stdin)\n"
"  -l,--logfile=FILE     write error and debug data to FILE (default=none)\n"
"     --logfile-fd=FD    write error and debug data to file desctiptor FD\n"
"  -f,--force            if an output file already exists, overwrite it\n"
"     --inspect          inspect image on-the-fly for error records\n"
"  -v,--verbose          verbose output\n"
"  -d,--debug            debugging output\n"
"     --skip-COND        skip condition COND, and proceed anyway\n"
"     --warn-COND        warn on condition COND, but proceed anyway\n"
"     --fail-COND        warn on condition COND, and abort operation\n"
"  	  COND=any:        any condition\n"
"  	  COND=pidzero:    task with sid/pgid zero in a --no-pidns restart\n"
"  	  COND=mntproc:    /proc isn't already mounted at restart (def: warn)\n"
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

static long cond_to_mask(const char *cond)
{
	static struct {
		char *cond;
		long mask;
	} conditions[] = {
		{"pidzero", CKPT_COND_PIDZERO},
		{"mntproc", CKPT_COND_MNTPROC},
		{"any", CKPT_COND_ANY},
		{NULL, 0}
	};

	int i;

	for (i = 0; conditions[i].cond; i++)
		if (!strcmp(cond, conditions[i].cond))
			return conditions[i].mask;

	ckpt_err("restart: invalid warn/fail condition '%s'\n", cond);
	exit(1);
}

static int str2sig(char *str)
{
	int sig = 0;

	do {
		if (!strcmp(signal_array[sig].sigstr, str))
			return signal_array[sig].signum;
	} while (signal_array[++sig].signum >= 0);

	return -1;
}

static void parse_args(struct cr_restart_args *args, int argc, char *argv[])
{
	static struct option opts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "pidns",	no_argument,		NULL, 'p' },
		{ "no-pidns",	no_argument,		NULL, 'P' },
		{ "pids",	no_argument,		NULL, 3 },
		{ "self",	no_argument,		NULL, 6},
		{ "signal",	required_argument,	NULL, 4 },
		{ "inspect",	no_argument,		NULL, 5 },
		{ "keeplsm",	no_argument,		NULL, 'k' },
		{ "input",	required_argument,	NULL, 'i' },
		{ "input-fd",	required_argument,	NULL, 7 },
		{ "logfile",	required_argument,	NULL, 'l' },
		{ "logfile-fd",	required_argument,	NULL, 8 },
		{ "force",	no_argument,		NULL, 'f' },
		{ "root",	required_argument,	NULL, 'r' },
		{ "mntns",	no_argument,		NULL, 11 },
		{ "wait",	no_argument,		NULL, 'w' },
		{ "show-status",	no_argument,	NULL, 1 },
		{ "copy-status",	no_argument,	NULL, 2 },
		{ "no-wait",	no_argument,		NULL, 'W' },
		{ "freezer",	required_argument,	NULL, 'F' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ "debug",	no_argument,		NULL, 'd' },
		{ "warn-pidzero",	no_argument,	NULL, 9 },
		{ "fail-pidzero",	no_argument,	NULL, 10 },
		{ "mount-pty",	no_argument,		NULL, 12 },
		{ NULL,		0,			NULL, 0 }
	};
	static char optc[] = "hdvfkpPwWF:r:i:l:";

	int optind;
	int sig;
	int no_pidns;
	int klogfd;
	int infd;
	int force;
	int excl;

	char *klogfile;
	char *input;

	/* defaults */
	memset(args, 0, sizeof(*args));
	args->wait = 1;
	args->infd = fileno(stdin);
	args->ulogfd = fileno(stdout);
	args->uerrfd = fileno(stderr);
	args->klogfd = CHECKPOINT_FD_NONE;
	args->warn = CKPT_COND_WARN;
	args->fail = CKPT_COND_FAIL;

	no_pidns = 0;
	klogfd = -1;
	infd = -1;
	force = 0;

	klogfile = NULL;
	input = NULL;

	while (1) {
		int c = getopt_long(argc, argv, optc, opts, &optind);
		if (c == -1)
			break;
		switch (c) {
		case '?':
			exit(1);
		case 'h':
			usage(usage_str);
		case 'v':
			global_verbose = args->verbose = 1;
			break;
		case 5:  /* --inspect */
			args->inspect = 1;
			break;
		case 'i':
			input = optarg;
			break;
		case 7:
			infd = str2num(optarg);
			if (infd < 0) {
				ckpt_err("restart: invalid file descriptor\n");
				exit(1);
			}
			break;
		case 'l':
			klogfile = optarg;
			break;
		case 8:
			klogfd = str2num(optarg);
			if (klogfd < 0) {
				ckpt_err("restart: invalid file descriptor\n");
				exit(1);
			}
			break;
		case 'f':
			force = 1;
			break;
		case 'p':
			args->pidns = 1;
			break;
		case 'P':
			no_pidns = 1;
			break;
		case 6:  /* --self */
			args->self = 1;
			break;
		case 4:  /* --signal */
			sig = str2sig(optarg);
			if (sig < 0)
				sig = str2num(optarg);
			if (sig < 0 || sig >= NSIG) {
				ckpt_err("restart: invalid signal\n");
				exit(1);
			}
			global_send_sigint = sig;
			break;
		case 3:  /* --pids */
			args->pids = 1;
			args->pidns = 1;  /* implied */
			break;
		case 'r':
			args->root = optarg;
			break;
		case 'w':
			args->wait = 1;
			break;
		case 'W':
			args->wait = 0;
			break;
		case 'k':
			args->keep_lsm = 1;
			break;
		case 1:  /* --show-status */
			args->wait = 1;
			args->show_status = 1;
			break;
		case 2: /* --copy-status */
			args->wait = 1;
			args->copy_status = 1;
			break;
		case 'd':
			global_debug = args->debug = 1;
			break;
		case 'F':
			args->freezer = optarg;
			args->keep_frozen = 1;
			break;
		case 9:
			args->warn |= cond_to_mask(&opts[optind].name[5]);
			break;
		case 10:
			args->fail |= cond_to_mask(&opts[optind].name[5]);
			break;
		case 11:
			args->mntns = 1;
			break;
		case 12:
			args->mnt_pty = 1;
			break;
		default:
			usage(usage_str);
		}
	}

	if (no_pidns)
		args->pidns = 0;

	if (args->self && no_pidns) {
		ckpt_err("Invalid mix of --self with multiprocess options\n");
		exit(1);
	}

	if (input && infd >= 0) {
		ckpt_err("Invalid use of both -i/--input and --input-fd\n");
		exit(1);
	}

	/* input file ? */
	if (input) {
		args->infd = open(input, O_RDONLY, 0);
		if (args->infd < 0) {
			ckpt_perror("open input file");
			exit(1);
		}
	} else if (infd >= 0)
		args->infd = infd;

	if (klogfile && klogfd >= 0) {
		ckpt_err("Invalid use of both -l/--logfile and --logfile-fd\n");
		exit(1);
	}

	excl = force ? 0 : O_EXCL;

	/* (optional) log file */
	if (klogfile) {
		args->klogfd = open(klogfile, O_RDWR | O_CREAT | excl, 0644);
		if (args->klogfd < 0) {
			ckpt_perror("open log file");
			exit(1);
		}
	} else if (klogfd >= 0)
		args->klogfd = klogfd;
}

int main(int argc, char *argv[])
{
	int ret;
	struct cr_restart_args args;

	/*
	 * Initialize the log/error fds early so even parse_args() errors
	 * are redirected here. Even if we later implement command line options
	 * that override these, any errors/messages that occur before those
	 * new options are parsed still go to stdout/stderr
	 */
	global_ulogfd = fileno(stdout);
	global_uerrfd = fileno(stderr);

	parse_args(&args, argc, argv);

	ret = cr_restart(&args);

	return (ret >= 0) ? 0 : 1;
}

