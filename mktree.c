/*
 *  mktree.c: restart of multiple processes
 *
 *  Copyright (C) 2008-2009 Oren Laadan
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include <linux/sched.h>
#include <linux/checkpoint.h>
#include <linux/checkpoint_hdr.h>

static char usage_str[] =
"usage: mktree [opts]\n"
"  mktree restores from a checkpoint image by first creating in userspace\n"
"  the original tasks tree, and then calling sys_restart by each task.\n"
"\tOptions:\n"
"\t -h,--help             print this help message\n"
"\t -p,--pidns            create a new pid namspace (default with --pids)\n"
"\t    --pidns-intr=SIG   send SIG to root task on SIGINT (default: SIGKILL)\n"
"\t -P,--no-pidns         do not create a new pid namspace (default)\n"
"\t    --pids             restore original pids (default with --pidns)\n"
"\t -w,--wait             wait for (root) task to termiate (default)\n"
"\t    --show-status      show exit status of (root) task (implies -w)\n"
"\t    --copy-status      imitate exit status of (root) task (implies -w)\n"
"\t -W,--no-wait          do not wait for (root) task to terminate\n"
"\t -v,--verbose          verbose output\n"
"\t -d,--debug            debugging output\n"
"";

/*
 * By default, 'mktree' creates a new pid namespace in which the
 * restart takes place, using the original pids from the time of the
 * checkpoint. This requires that CLONE_NEWPID and clone_with_pids()
 * be enabled.
 *
 * Restart can also occur in the current namespace, however pids from
 * the time of the checkpoint may be already in use then. Therefore,
 * by default, 'mktree' creates an equivalen tree without restoring
 * the original pids, assuming that the application can tolerate this.
 * For this, the 'ckpt_hdr_pids' array is transformed on-the-fly
 * before it is fed to the kernel.
 *
 * By default, "--pids" implied "--pidns" and vice-versa. The user can
 * use "--pids --no-pidns" for a restart in the currnet namespace -
 * 'mktree' will attempt to create the new tree with the original pids
 * from the time of the checkpoint, if possible. This requires that
 * clone_with_pids() be enabled.
 *
 * To re-create the tasks tree in user space, 'mktree' reads the
 * header and tree data from the checkpoint image tree. It makes up
 * for the data that was consumed by using a helper process that
 * provides the data back to the restart syscall, followed by the rest
 * of the checkpoint image stream.
 */

#ifdef CHECKPOINT_DEBUG
#define ckpt_dbg(_format, _args...)					\
	do {								\
		if (global_debug)					\
			fprintf(stderr, "<%d>" _format, _gettid(), ##_args); \
	} while (0)
#define ckpt_dbg_cont(_format, _args...)			\
	do {							\
		if (global_debug)				\
			fprintf(stderr, _format, ##_args);	\
	} while (0)
#else
#define ckpt_dbg(_format, _args...)  \
	do { } while (0)
#define ckpt_dbg_cont(_format, _args...)  \
	do { } while (0)
#endif

#define ckpt_err(...)  \
	fprintf(stderr, __VA_ARGS__)

#define ckpt_verbose(...)			\
	do {					\
		if (global_verbose)		\
			printf(__VA_ARGS__);	\
	} while(0)

inline static int restart(pid_t pid, int fd, unsigned long flags)
{
	return syscall(__NR_restart, pid, fd, flags);
}

#define BUFSIZE  (4 * 4096)

struct hashent {
	long key;
	void *data;
	struct hashent *next;
};

struct task;
struct ckpt_ctx;

struct task {
	int flags;		/* state and (later) actions */

	struct task *children;	/* pointers to first child, next and prev */
	struct task *next_sib;	/*   sibling, and the creator of a process */
	struct task *prev_sib;
	struct task *creator;

	struct task *phantom;	/* pointer to place-holdler task (if any) */

	pid_t pid;		/* process IDs, our bread-&-butter */
	pid_t ppid;
	pid_t tgid;
	pid_t sid;
	
	pid_t rpid;		/* [restart without vpids] actual (real) pid */

	struct ckpt_ctx *ctx;	/* points back to the c/r context */
};

#define TASK_ROOT	0x1	/* */
#define TASK_DEAD	0x2	/* */
#define TASK_THREAD	0x4	/* */
#define TASK_SIBLING	0x8	/* */
#define TASK_SESSION	0x10	/* */
#define TASK_NEWPID	0x20	/* */

struct ckpt_ctx {
	pid_t init_pid;
	int pipe_in;
	int pipe_out;
	int pids_nr;

	int pipe_child[2];	/* for children to report status */
	int pipe_feed[2];	/* for feeder to provide input */

	struct ckpt_hdr_pids *pids_arr;

	struct task *tasks_arr;
	int tasks_nr;
	int tasks_max;
	int tasks_pid;

	struct hashent **hash_arr;
	
	char header[BUFSIZE];
	char header_arch[BUFSIZE];
	char tree[BUFSIZE];
	char buf[BUFSIZE];
	struct args *args;
};

/* this really belongs to some kernel header ! */
struct target_pid_set {
	int num_pids;
	pid_t *target_pids;
};

int global_debug;
int global_verbose;
pid_t global_child_pid;
pid_t global_parent_pid;
int global_child_status;
int global_child_collected;
int global_send_sigint = -1;
int global_sent_sigint;

static int ckpt_build_tree(struct ckpt_ctx *ctx);
static int ckpt_init_tree(struct ckpt_ctx *ctx);
static int ckpt_set_creator(struct ckpt_ctx *ctx, struct task *task);
static int ckpt_placeholder_task(struct ckpt_ctx *ctx, struct task *task);
static int ckpt_propagate_session(struct ckpt_ctx *ctx, struct task *session);

static int ckpt_coordinator_pidns(struct ckpt_ctx *ctx);
static int ckpt_coordinator(struct ckpt_ctx *ctx);

static int ckpt_make_tree(struct ckpt_ctx *ctx, struct task *task);
static int ckpt_collect_child(struct ckpt_ctx *ctx);
static pid_t ckpt_fork_child(struct ckpt_ctx *ctx, struct task *child);
static int ckpt_adjust_pids(struct ckpt_ctx *ctx);

static void ckpt_abort(struct ckpt_ctx *ctx, char *str);
static int ckpt_do_feeder(void *data);
static int ckpt_fork_feeder(struct ckpt_ctx *ctx);

static int ckpt_write(int fd, void *buf, int count);
static int ckpt_write_obj(struct ckpt_ctx *ctx, struct ckpt_hdr *h);

static int ckpt_write_header(struct ckpt_ctx *ctx);
static int ckpt_write_header_arch(struct ckpt_ctx *ctx);
static int ckpt_write_tree(struct ckpt_ctx *ctx);

static int ckpt_read(int fd, void *buf, int count);
static int ckpt_read_obj(struct ckpt_ctx *ctx,
			 struct ckpt_hdr *h, void *buf, int n);
static int ckpt_read_obj_type(struct ckpt_ctx *ctx, void *b, int n, int type);

static int ckpt_read_header(struct ckpt_ctx *ctx);
static int ckpt_read_header_arch(struct ckpt_ctx *ctx);
static int ckpt_read_tree(struct ckpt_ctx *ctx);

static int clone_with_pids(int (*fn)(void *), void *child_stack, int flags,
			   struct target_pid_set *target_pids, void *arg);

static int hash_init(struct ckpt_ctx *ctx);
static void hash_exit(struct ckpt_ctx *ctx);
static int hash_insert(struct ckpt_ctx *ctx, long key, void *data);
static void *hash_lookup(struct ckpt_ctx *ctx, long key);

static inline pid_t _gettid(void)
{
	return syscall(__NR_gettid);
}

static inline pid_t _getpid(void)
{
	return syscall(__NR_getpid);
}

struct pid_swap {
	pid_t old;
	pid_t new;
};

struct args {
	int pids;
	int pidns;
	int wait;
	int show_status;
	int copy_status;
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
		{ "pidns",	no_argument,		NULL, 'p' },
		{ "pidns-signal",	required_argument,	NULL, '4' },
		{ "no-pidns",	no_argument,		NULL, 'P' },
		{ "pids",	no_argument,		NULL, 3 },
		{ "wait",	no_argument,		NULL, 'w' },
		{ "show-status",	no_argument,	NULL, 1 },
		{ "copy-status",	no_argument,	NULL, 2 },
		{ "no-wait",	no_argument,		NULL, 'W' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ "debug",	no_argument,		NULL, 'd' },
		{ NULL,		0,			NULL, 0 }
	};
	static char optc[] = "hdvpPwW";

	int sig;

	/* defaults */
	memset(args, 0, sizeof(*args));
	args->wait = 1;

	while (1) {
		int c = getopt_long(argc, argv, optc, opts, NULL);
		if (c == -1)
			break;
		switch (c) {
		case '?':
			exit(1);
		case 'h':
			usage(usage_str);
		case 'v':
			global_verbose = 1;
			break;
		case 'p':
			args->pidns = 1;
			break;
		case 'P':
			args->pidns = 0;
			break;
		case 4:
			sig = atoi(optarg);
			if (sig < 0 || sig >= NSIG) {
				printf("mktree: invalid signal number\n");
				exit(1);
			}
			global_send_sigint = sig;
			break;
		case 3:
			args->pids = 1;
			args->pidns = 1;  /* implied */
			break;
		case 'w':
			args->wait = 1;
			break;
		case 'W':
			args->wait = 0;
			break;
		case 1:
			args->wait = 1;
			args->show_status = 1;
			break;
		case 2:
			args->wait = 1;
			args->copy_status = 1;
			break;
		case 'd':
			global_debug = 1;
			break;
		default:
			usage(usage_str);
		}
	}

#ifndef CLONE_NEWPID
	if (args->pidns) {
		printf("This version of mktree was compiled without "
		       "support for --pidns.\n");
		exit(1);
	}
#endif

#ifndef CHECKPOINT_DEBUG
	if (global_debug) {
		printf("This version of mktree was compiled without "
		       "support for --debug.\n");
		exit(1);
	}
#endif

	if (args->pidns)
		args->pids = 1;

#ifndef __NR_clone_with_pids
	if (args->pids) {
		printf("This version of mktree was compiled without "
		       "support for --pids.\n");
		exit(1);
	}
#endif
}

static void report_exit_status(int status, char *str, int debug)
{
	char msg[64];

	if (WIFEXITED(status))
		sprintf(msg, "%s exited status %d", str, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		sprintf(msg, "%s killed signal %d", str, WTERMSIG(status));
	else
		sprintf(msg, "%s dies somehow ... raw status %d", str, status);

	if (debug)
		ckpt_dbg("%s\n", msg);
	else
		ckpt_err("%s\n", msg);
}

static void sigchld_handler(int sig)
{
	int collected = 0;
	int status;
	pid_t pid;

	while (1) {
		pid = waitpid(-1, &status, WNOHANG | __WALL);
		if (pid == 0) {
			ckpt_dbg("SIGCHLD: child not ready\n");
			break;
		} else if (pid > 0) {
			/* inform collection coordinator or root-task */
			if (pid == global_child_pid) {
				global_child_status = status;
				global_child_collected = 1;
				report_exit_status(status, "SIGCHLD: ", 1);
			}
			ckpt_dbg("SIGCHLD: collected child %d\n", pid);
			collected = 1;
		} else if (errno == EINTR) {
			ckpt_dbg("SIGCHLD: waitpid interrupted\n");
		} else if (errno == ECHILD) {
			break;
		} else {
			perror("WEIRD !! child collection failed");
			exit(1);
		}
	}

	if (!collected)
		ckpt_dbg("SIGCHLD: already collected\n");
}

static void sigint_handler(int sig)
{
	pid_t pid = global_child_pid;

	ckpt_verbose("SIGINT sent to restarted tasks\n");

	if (pid) {
		ckpt_dbg("delegating SIGINT to child %d "
			 "(coordinator or root task)\n", pid);
		kill(-pid, SIGINT);
		kill(pid, SIGINT);
	}
}

int main(int argc, char *argv[])
{
	struct ckpt_ctx ctx;
	struct args args;
	int ret;

	memset(&ctx, 0, sizeof(ctx));

	if (hash_init(&ctx) < 0)
		exit(1);

	parse_args(&args, argc, argv);

	ctx.args = &args;

	setpgrp();

	ret = ckpt_read_header(&ctx);
	if (ret < 0) {
		perror("read c/r header");
		exit(1);
	}
		
	ret = ckpt_read_header_arch(&ctx);
	if (ret < 0) {
		perror("read c/r header arch");
		exit(1);
	}

	ret = ckpt_read_tree(&ctx);
	if (ret < 0) {
		perror("read c/r tree");
		exit(1);
	}

	ret = ckpt_fork_feeder(&ctx);
	if (ret < 0)
		exit(1);

	/* build creator-child-relationship tree */
	ret = ckpt_build_tree(&ctx);
	if (ret < 0)
		exit(1);

	hash_exit(&ctx);

	if (ctx.args->pidns && ctx.tasks_arr[0].pid != 1) {
		ckpt_dbg("new pidns without init\n");
		if (global_send_sigint == -1)
			global_send_sigint = SIGINT;
		ret = ckpt_coordinator_pidns(&ctx);
	} else if (ctx.args->pidns) {
		ckpt_dbg("new pidns with init\n");
		ctx.tasks_arr[0].flags |= TASK_NEWPID;
		if (global_send_sigint == -1)
			global_send_sigint = SIGKILL;
		ret = ckpt_coordinator(&ctx);
	} else {
		ckpt_dbg("subtree (existing pidns)\n");
		if (global_send_sigint == -1)
			global_send_sigint = SIGINT;
		ret = ckpt_coordinator(&ctx);
	}

	return ret;
}

static int ckpt_parse_status(int status, int mimic, int verbose)
{
	int sig = 0;
	int ret = 0;

	if (verbose && global_sent_sigint)
		printf("Terminated\n");
	if (WIFSIGNALED(status)) {
		sig = WTERMSIG(status);
		if (verbose && !global_sent_sigint)
			printf("Killed %d\n", sig);
		ckpt_dbg("task terminated with signal %d\n", sig);
	} else if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (verbose)
			printf("Exited %d\n", ret);
		ckpt_dbg("task exited with status %d\n", ret);
	}

	if (mimic) {
		if (sig) {
			ckpt_dbg("mimic sig %d\n", sig);
			kill(_getpid(), sig);
		} else {
			ckpt_dbg("mimic ret %d\n", ret);
			return ret;
		}
	}

	return 0;
}

static int ckpt_collect_child(struct ckpt_ctx *ctx)
{
	int mimic = ctx->args->copy_status;
	int verbose = ctx->args->show_status;
	int status;
	pid_t pid;

	/*
	 * if sigchld_handler() collected the child by now, it set
	 * @global_child_collected and then left the status inside
	 * @global_child_status.
	 */
	while (!global_child_collected) {
		pid = waitpid(global_child_pid, &status, __WALL);
		if (pid == global_child_pid)
			break;
	}
	/*
	 * moreover, the child may have terminated right before the
	 * call to waitpid()
	 */
	if (global_child_collected) {
		status = global_child_status;
	} else if (pid < 0) {
		perror("WEIRD: collect child task");
		exit(1);
	}

	return ckpt_parse_status(status, mimic, verbose);
}

static int ckpt_pretend_reaper(struct ckpt_ctx *ctx)
{
	int status;
	pid_t pid;

	while (1) {
		pid = waitpid(-1, &status, __WALL);
		if (pid < 0 && errno == ECHILD)
			break;
		if (!global_child_collected && pid == global_child_pid) {
			global_child_collected = 1;
			global_child_status = status;
		}
	}

	return ckpt_parse_status(global_child_status, 1, 0);
}

static int ckpt_probe_child(pid_t pid, char *str)
{
	int status, ret;

	/* use waitpid() to probe that a child is still alive */
	ret = waitpid(pid, &status, WNOHANG);
	if (ret == pid) {
		report_exit_status(status, str, 0);
		exit(1);
	} else if (ret < 0 && errno == ECHILD) {
		ckpt_err("WEIRD: %s exited without trace (%s)\n",
			 str, strerror(errno));
		exit(1);
	} else if (ret != 0) {
		ckpt_err("waitpid for %s (%s)", str, strerror(errno));
		exit(1);
	}
	return 0;
}

#ifdef CLONE_NEWPID
static int __ckpt_coordinator(void *arg)
{
	return ckpt_coordinator((struct ckpt_ctx *) arg);
}

static int ckpt_coordinator_pidns(struct ckpt_ctx *ctx)
{
	void *stk = NULL;
	pid_t coord_pid;
	int copy;

	ckpt_dbg("forking coordinator in new pidns\n");

	stk = malloc(PTHREAD_STACK_MIN);
	if (!stk) {
		perror("coordinator stack malloc");
		return -1;
	}
	stk += PTHREAD_STACK_MIN;

	copy = ctx->args->copy_status;
	ctx->args->copy_status = 1;

	coord_pid = clone(__ckpt_coordinator, stk, CLONE_NEWPID|SIGCHLD, ctx);
	free(stk - PTHREAD_STACK_MIN);
	if (coord_pid < 0) {
		perror("clone coordinator");
		return coord_pid;
	}
	global_child_pid = coord_pid;

	/* catch SIGCHLD to detect errors in coordinator */
	signal(SIGCHLD, sigchld_handler);
	/* catch SIGINT to propagate ctrl-c to the coordinator */
	signal(SIGINT, sigint_handler);

	/*
	 * The child (coordinator) may have already exited before the
	 * signal handler was plugged; verify that it's still there.
	 */
	if (ckpt_probe_child(coord_pid, "coordinator") < 0)
		return -1;

	ctx->args->copy_status = copy;
	if (ctx->args->wait)
		return ckpt_collect_child(ctx);
	else
		return 0;
}
#else
static int ckpt_coordinator_pidns(struct ckpt_ctx *ctx, int *status)
{
	printf("logical error: ckpt_coordinator_pidns unexpected\n");
	exit(1);
}
#endif

static int ckpt_coordinator(struct ckpt_ctx *ctx)
{
	pid_t root_pid;
	int ret;

	root_pid = ckpt_fork_child(ctx, &ctx->tasks_arr[0]);
	if (root_pid < 0)
		exit(1);
	global_child_pid = root_pid;

	/* catch SIGCHLD to detect errors during hierarchy creation */
	signal(SIGCHLD, sigchld_handler);
	/* catch SIGINT to propagate ctrl-c to the restarted tasks */
	signal(SIGINT, sigint_handler);

	/*
	 * The child (root_task) may have already exited before the
	 * signal handler was plugged; verify that it's still there.
	 */
	if (ckpt_probe_child(root_pid, "root task") < 0)
		exit(1);

	ret = restart(root_pid, STDIN_FILENO, 0);

	if (ret < 0) {
		perror("restart failed");
		ckpt_verbose("Failed\n");
		ckpt_dbg("restart failed ?\n");
		exit(1);
	}

	ckpt_verbose("Success\n");
	ckpt_dbg("restart succeeded\n");

	if (ctx->args->pidns && ctx->tasks_arr[0].pid != 1) {
		/*
		 * If root task isn't container init, we must stay
		 * around and be reaper until all tasks are gone.
		 * Otherwise, container will die as soon as we exit.
		 */
		ret = ckpt_pretend_reaper(ctx);
	} else if (ctx->args->wait) {
		ret = ckpt_collect_child(ctx);
	} else {
		ret = 0;
	}

	if (ret < 0)
		ckpt_dbg("c/r failed ?\n");
	else
		ckpt_dbg("c/r succeeded\n");

	return ret;
}

static inline struct task *ckpt_init_task(struct ckpt_ctx *ctx)
{
	return (&ctx->tasks_arr[0]);
}

/*
 * ckpt_build_tree - build the task tree data structure which provides
 * the "instructions" to re-create the task tree
 */
static int ckpt_build_tree(struct ckpt_ctx *ctx)
{
	struct task *task;
	int i;

	/*
	 * Allow for additional tasks to be added on demand for
	 * referenced pids of dead tasks (each task can introduce at
	 * most two: session and process group IDs), as well as for
	 * placeholder tasks (each session id may have at most one)
	 */
	ctx->tasks_max = ctx->pids_nr * 4;
	ctx->tasks_arr = malloc(sizeof(*ctx->tasks_arr) * ctx->tasks_max);
	if (!ctx->tasks_arr) {
		perror("malloc tasks array");
		return -1;
	}

	/* initialize tree */
	if (ckpt_init_tree(ctx) < 0) {
		free(ctx->tasks_arr);
		ctx->tasks_arr = NULL;
		return -1;
	}

	/* assign a creator to each task */
	for (i = 0; i < ctx->tasks_nr; i++) {
		task = &ctx->tasks_arr[i];
		if (task == ckpt_init_task(ctx))
			continue;
		if (task->creator)
			continue;
		if (ckpt_set_creator(ctx, task) < 0) {
			free(ctx->tasks_arr);
			ctx->tasks_arr = NULL;
			return -1;
		}
	}

#ifdef CHECKPOINT_DEBUG
	for (i = 0; i < ctx->tasks_nr; i++) {
		task = &ctx->tasks_arr[i];
		ckpt_dbg("pid %d ppid %d sid %d creator %d",
		       task->pid, task->ppid, task->sid,
		       task->creator ? task->creator->pid : 0);
		if (task->next_sib)
			ckpt_dbg_cont(" next %d", task->next_sib->pid);
		if (task->prev_sib)
			ckpt_dbg_cont(" prev %d", task->prev_sib->pid);
		if (task->phantom)
			ckpt_dbg_cont(" placeholder %d", task->phantom->pid);
		ckpt_dbg_cont(" %c%c%c%c",
		       (task->flags & TASK_THREAD) ? 'T' : ' ',
		       (task->flags & TASK_SIBLING) ? 'P' : ' ',
		       (task->flags & TASK_SESSION) ? 'S' : ' ',
		       (task->flags & TASK_DEAD) ? 'D' : ' ');
		ckpt_dbg_cont("\n");
	}
#endif

	return 0;
}		

static int ckpt_setup_task(struct ckpt_ctx *ctx, pid_t pid)
{
	struct task *task;

	if (hash_lookup(ctx, pid))
		return 0;

	task = &ctx->tasks_arr[ctx->tasks_nr++];

	task->flags = TASK_DEAD;

	task->pid = pid;
	task->ppid = ckpt_init_task(ctx)->pid;
	task->tgid = pid;
	task->sid = pid;

	task->children = NULL;
	task->next_sib = NULL;
	task->prev_sib = NULL;
	task->creator = NULL;

	task->rpid = -1;
	task->ctx = ctx;

	if (hash_insert(ctx, pid, task) < 0)
		return -1;

	/* remember the max pid seen */
	if (task->pid > ctx->tasks_pid)
		ctx->tasks_pid = task->pid;

	return 0;
}

static int ckpt_init_tree(struct ckpt_ctx *ctx)
{
	struct task *task;
	pid_t init_sid;
	pid_t init_pid;
	pid_t init_pgid;
	int i;

	init_pid = ctx->pids_arr[0].vpid;
	init_sid = ctx->pids_arr[0].vsid;
	init_pgid = ctx->pids_arr[0].vpgid;

	/* XXX for out-of-container subtrees */
	for (i = 0; i < ctx->pids_nr; i++) {
		if (ctx->pids_arr[i].vsid == init_sid)
			ctx->pids_arr[i].vsid = init_pid;
		if (ctx->pids_arr[i].vpgid == init_sid)
			ctx->pids_arr[i].vpgid = init_pid;
		if (ctx->pids_arr[i].vpgid == init_pgid)
			ctx->pids_arr[i].vpgid = init_pid;
	}

	/* populate with known tasks */
	for (i = 0; i < ctx->pids_nr; i++) {
		task = &ctx->tasks_arr[i];

		task->flags = 0;

		task->pid = ctx->pids_arr[i].vpid;
		task->ppid = ctx->pids_arr[i].vppid;
		task->tgid = ctx->pids_arr[i].vtgid;
		task->sid = ctx->pids_arr[i].vsid;

		task->children = NULL;
		task->next_sib = NULL;
		task->prev_sib = NULL;
		task->creator = NULL;

		task->rpid = -1;
		task->ctx = ctx;

		if (hash_insert(ctx, task->pid, task) < 0)
			return -1;
	}

	ctx->tasks_nr = ctx->pids_nr;

	/* add pids unaccounted for (no tasks) */
	for (i = 0; i < ctx->pids_nr; i++) {
		if (ckpt_setup_task(ctx, ctx->pids_arr[i].vsid) < 0)
			return -1;
		if (ckpt_setup_task(ctx, ctx->pids_arr[i].vpgid) < 0)
			return -1;
	}

	/* mark root task(s) */
	ctx->tasks_arr[0].flags |= TASK_ROOT;

	return 0;
}

/*
 * Algorithm DumpForest
 * "Transparent Checkpoint/Restart of Multiple Processes on Commodity
 * Operating Systems" in USENIX 2007
 * http://www.usenix.org/events/usenix07/tech/full_papers/laadan/laadan_html/paper.html
 *
 * The algorithm captures the state of the task forest. It considers
 * all pid values, even of dead tasks (appearing in sid/pgid of other
 * tasks). The input is a table with all pids; the output is a tree
 * structure imposed on that table. The goal of is to determine the
 * creating parent (creator) of each task. At restart, the init task
 * will recursively create the remaining tasks as instructed by the
 * table.
 *
 * Each entry in the table consists of the following set of fields:
 * flags, pid, tgid, sid, pgid, and pointers to the a creator, next
 * and previous sibling, and first child task. Note that the creator
 * may not necessarily correspond to the parent. The possible flags
 * are TASK_DEAD, TASK_THREAD, TASK_SESSION (that asks inherit a
 * session id), and TASK_SIBLING (that asks to inherit the parent via
 * CLONE_PARENT). The algorithm loops through all the entries in the
 * table:
 *
 * If the entry is a thread and not the thread group leader, we set
 * the creator to be the thread group leader and set TASK_THREAD.
 *
 * Otherwise, if the entry is a session leader, it must have called
 * setsid(), and does not need to inherit its session. The creator is
 * set to its real parent.
 *
 * Otherwise, if the entry is a dead task (no current task exists
 * with the given pid), the only constraint is that it inherit the
 * correct session id. The session leader is set as its creator.
 *
 * Otherwise, if the entry is an orphan task, it cannot inherit the
 * correct session id from init. We add a placeholder task in the
 * table whose function on restart is to inherit the session id from
 * the session leader, create the task, then terminate so that the
 * task will be orphaned. The placeholder is given an arbitrary pid
 * not already in the table, and the sid identifying the session, and
 * is marked TASK_DEAD.
 *
 * Otherwise, if the entry's sid is equal to its parent's, the only
 * constraint is that it inherit the correct session id from its
 * parent. This is simply done by setting its parent as its creator.
 *
 * Otherwise, the entry corresponds to a task which is not a session
 * leader, does not share the session id with its parent, and hence
 * whose session id must be inherited from an ancestor further up the
 * tree forest. The task was forked by its parent before the parent
 * changed its own sid. Its creator is set to be its parent, and it is
 * marked TASK_SESSION. This flag is propagated up its ancestry until
 * reaching an entry with that session id. This ensures that the sid
 * correctly descend via inheritance to the current entry.
 *
 * If the traversal fails to find an entry with the same sid, it will
 * stop at an entry of a leader of another session. This entry must
 * have formerly been a descendant of the original session leader.
 * Its creator will have already been set init.  Because we now know
 * that it needs to pass the original sid to its own descendants, we
 * re-parent the entry to become a descendant of the original session
 * leader.  This is done using a placeholder in a manner similar to
 * how we handle orphans that are not session leaders.
 */
static int ckpt_set_creator(struct ckpt_ctx *ctx, struct task *task)
{
	struct task *session = hash_lookup(ctx, task->sid);
	struct task *parent = hash_lookup(ctx, task->ppid);
	struct task *creator;

	if (task == ckpt_init_task(ctx)) {
		ckpt_err("pid %d: init - no creator\n", ckpt_init_task(ctx)->pid);
		return -1;
	}

	if (task->tgid != task->pid) {
		/* thread: creator is thread-group-leader */
		ckpt_dbg("pid %d: thread tgid %d\n", task->pid, task->tgid);
		creator = hash_lookup(ctx, task->tgid);
		task->flags |= TASK_THREAD;
	} else if (task->pid == task->sid) {
		/* session leader: creator is parent */
		ckpt_dbg("pid %d: session leader\n", task->pid);
		creator = parent;
	} else if (task->flags & TASK_DEAD) {
		/* dead: creator is session leader */
		ckpt_dbg("pid %d: task is dead\n", task->pid);
		creator = session;
	} else if (task->sid == parent->sid) {
		/* (non-session-leader) inherit: creator is parent */
		ckpt_dbg("pid %d: inherit sid %d\n", task->pid, task->sid);
		creator = parent;
	} else if (task->ppid == 1) {
		/* (non-session-leader) orphan: creator is dummy */
		ckpt_dbg("pid %d: orphan session %d\n", task->pid, task->sid);
		if (!session->phantom)
			if (ckpt_placeholder_task(ctx, task) < 0)
				return -1;
		creator = session->phantom;
	} else {
		/* first make sure we know the session's creator */
		if (!session->creator && session != ckpt_init_task(ctx)) {
			/* (non-session-leader) recursive: session's creator */
			ckpt_dbg("pid %d: recursive session creator %d\n",
			       task->pid, task->sid);
			if (ckpt_set_creator(ctx, session) < 0)
				return -1;
		}
		/* then use it to decide what to do */
		if (session->creator->pid == task->ppid) {
			/* init must not be sibling creator (CLONE_PARENT) */
			if (session == ckpt_init_task(ctx)) {
				ckpt_err("pid %d: sibling session prohibited"
				       " with init as creator\n", task->pid);
				return -1;
			}
			/* (non-session-leader) sibling: creator is sibling */
			ckpt_dbg("pid %d: sibling session %d\n",
			       task->pid, task->sid);
			creator = session;
			task->flags |= TASK_SIBLING;
		} else {
			/* (non-session-leader) session: fork before setsid */
			ckpt_dbg("pid %d: propagate session %d\n",
			       task->pid, task->sid);
			creator = parent;
			task->flags |= TASK_SESSION;
		}
	}

	if (creator->children) {
		struct task *next = creator->children;

		task->next_sib = next;
		next->prev_sib = task;
	}

	ckpt_dbg("pid %d: creator set to %d\n", task->pid, creator->pid);
	task->creator = creator;
	creator->children = task;

	if (task->flags & TASK_SESSION)
		if (ckpt_propagate_session(ctx, task) < 0)
			return -1;

	return 0;
}

static int ckpt_placeholder_task(struct ckpt_ctx *ctx, struct task *task)
{
	struct task *session = hash_lookup(ctx, task->sid);
	struct task *holder = &ctx->tasks_arr[ctx->tasks_nr++];
	int n = 0;

	if (ctx->tasks_nr > ctx->tasks_max) {
		/* shouldn't happen, beacuse we prepared enough */
		ckpt_err("out of space in task table !");
		return -1;
	}

	/*
	 * allocate an unused pid for the placeholder
	 * (this will become inefficient if pid-space is exhausted)
	 */
	do {
		if (ctx->tasks_pid == INT_MAX)
			ctx->tasks_pid = 2;
		else
			ctx->tasks_pid++;

		if (n++ == INT_MAX) {	/* ohhh... */
			ckpt_err("pid namsepace exhausted");
			return -1;
		}
	} while (hash_lookup(ctx, ctx->tasks_pid));

	holder->flags = TASK_DEAD;

	holder->pid = ctx->tasks_pid;
	holder->ppid = ckpt_init_task(ctx)->pid;
	holder->tgid = holder->pid;
	holder->sid = task->sid;

	holder->children = NULL;
	holder->next_sib = NULL;
	holder->prev_sib = NULL;
	holder->creator = NULL;

	holder->rpid = -1;
	holder->ctx = ctx;

	holder->creator = session;
	if (session->children) {
		holder->next_sib = session->children;
		session->children->prev_sib = holder;
	}
	session->children = holder;
	session->phantom = holder;

	/* reparent entry if necssary */
	if (task->next_sib)
		task->next_sib->prev_sib = task->prev_sib;
	if (task->prev_sib)
		task->prev_sib->next_sib = task->next_sib;
	if (task->creator)
		task->creator->children = task->next_sib;

	task->creator = holder;
	task->next_sib = NULL;
	task->prev_sib = NULL;

	return 0;
}

static int ckpt_propagate_session(struct ckpt_ctx *ctx, struct task *task)
{
	struct task *session = hash_lookup(ctx, task->sid);
	struct task *creator;
	pid_t sid = task->sid;

	do {
		ckpt_dbg("pid %d: set session\n", task->pid);
		task->flags |= TASK_SESSION;

		creator = task->creator;
		if (creator->pid == 1) {
			if (ckpt_placeholder_task(ctx, task) < 0)
				return -1;
		}

		ckpt_dbg("pid %d: moving up to %d\n", task->pid, creator->pid);
		task = creator;

		if(!task->creator && task != ckpt_init_task(ctx)) {
			if (ckpt_set_creator(ctx, task) < 0)
				return -1;
		}
	} while (task->sid != sid &&
		 task != ckpt_init_task(ctx) &&
		 !(task->flags & TASK_SESSION) &&
		 task->creator != session);

	return 0;
}

/*
 * Algorithm MakeForest
 * "Transparent Checkpoint/Restart of Multiple Processes on Commodity
 * Operating Systems" in USENIX 2007
 * http://www.usenix.org/events/usenix07/tech/full_papers/laadan/laadan_html/paper.html
 *
 * The algorithm reconstructs the task hierarchy and relationships.
 * It works in a recursive manner by following the instructions set
 * forth by the task forest data structure. It begins with a single
 * init task, that will fork the tasks that have init set as their
 * creator. Each task then creates its own children.
 *
 * The algorithm loops through the list of children of a task three
 * times, during which the children are forked or cleaned up.  Each
 * child that is forked executes the same algorithm recursively until
 * all tasks have been created.
 *
 * In the first pass the current task spawns children that are marked
 * with TASK_SESSION and thereby need to be forked before the current
 * session id is changed.  The tasks then changes its session id if
 * needed. In the second pass the task forks the remainder of the
 * children. In both passes, a child that is marked TASK_THREAD is
 * created as a thread and a child that is marked TASK_SIBLING is
 * created with parent inheritance. In the third pass, terminated
 * tasks and temporary placeholders are cleaned up. Finally, the task
 * either terminates if it is marked TASK_DEAD or calls sys_restart()
 * which does not return.
 */
static int ckpt_make_tree(struct ckpt_ctx *ctx, struct task *task)
{
	struct task *child;
	struct pid_swap swap;
	pid_t newpid;
	int ret;

	ckpt_dbg("pid %d: pid %d sid %d parent %d\n",
	       task->pid, _gettid(), getsid(0), getppid());

	/* 1st pass: fork children that inherit our old session-id */
	for (child = task->children; child; child = child->next_sib) {
		if (child->flags & TASK_SESSION) {
			ckpt_dbg("pid %d: fork child %d with session\n",
			       task->pid, child->pid);
			newpid = ckpt_fork_child(ctx, child);
			if (newpid < 0)
				return -1;
			child->rpid = newpid;
		}
	}

	/* change session id, if necessary */
	if (task->pid == task->sid) {
		ret = setsid();
		if (ret < 0 && task != ckpt_init_task(ctx)) {
			perror("setsid");
			return -1;
		}
	}

	/* 2st pass: fork children that inherit our new session-id */
	for (child = task->children; child; child = child->next_sib) {
		if (!(child->flags & TASK_SESSION)) {
			ckpt_dbg("pid %d: fork child %d without session\n",
			       task->pid, child->pid);
			newpid = ckpt_fork_child(ctx, child);
			if (newpid < 0)
				return -1;
			child->rpid = newpid;
		}
	}
	
	/* 3rd pass: bring out your deads ... */
	for (child = task->children; child; child = child->next_sib) {
		if (child->flags & TASK_DEAD) {
			ret = waitpid(child->rpid, NULL, 0);
			if (ret < 0) {
				perror("waitpid");
				return -1;
			}
		}
	}

	/* are we supposed to exit now ? */
	if (task->flags & TASK_DEAD) {
		ckpt_dbg("pid %d: task dead ... exiting\n", task->pid);
		exit(0);
	}

	/*
	 * In '--no-pidns' (and not '--pids') mode we restart with
	 * pids different than originals, so report old/new pids via
	 * pipe to the feeder.
	 *
	 * However, even with '--pids', coordinator needs to create
	 * entire hierarchy before (in kernel) reading the image.
	 * Always reporting pids ensures that feeder only feeds data
	 * (and coodinator reads data), the when hierarchy is ready.
	 */

	/* communicate via pipe that all is well */
	swap.old = task->pid;
	swap.new = _gettid();
	ret = write(ctx->pipe_out, &swap, sizeof(swap));
	if (ret != sizeof(swap)) {
		perror("write swap");
		return -1;
	}
	close(ctx->pipe_out);

	/* on success this doesn't return */
	ckpt_dbg("about to call sys_restart()\n");
	ret = restart(0, STDIN_FILENO, 0);
	if (ret < 0)
		perror("task restore failed");
	return ret;
}

int ckpt_fork_stub(void *data)
{
	struct task *task = (struct task *) data;

	/*
	 * When restart without pids, we ensure prpoper cleanup of the
	 * new hierarchy in case of coordinator death by asking to be
	 * killed then. When restart succeeds, it will have replaced
	 * this with the original value.
	 *
	 * This works because in the --no-pids case, the hierarchy of
	 * tasks does not contain zombies (else, there must also be a
	 * container init, whose pid (==1) is clearly already taken.
	 *
	 * Thus, if a the parent of this task dies before this prctl()
	 * call, it suffices to test getppid() == global_parent_pid.
	 *
	 * (This also assumes that the hierarchy does not create new
	 * pid-namespaces during the restart).
	 */
	if (!task->ctx->args->pids) {
		if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0) {
			perror("prctl");
			return -1;
		}
		if (getppid() != global_parent_pid) {
			ckpt_err("[%d]: parent is MIA (%d != %d)\n",
				 _getpid(), getppid(), global_parent_pid);
			return -1;
		}
	}

	/* root has some extra work */
	if (task->flags & TASK_ROOT) {
		task->ctx->init_pid = _getpid();
		ckpt_dbg("root task pid %d\n", _getpid());
	}

	return ckpt_make_tree(task->ctx, task);
}

static pid_t ckpt_fork_child(struct ckpt_ctx *ctx, struct task *child)
{
	struct target_pid_set pid_set;
	void *stack = NULL;
	unsigned long flags = SIGCHLD;
	pid_t pid = 0;

	ckpt_dbg("forking child vpid %d flags %#x\n", child->pid, child->flags);

	stack = malloc(PTHREAD_STACK_MIN);
	if (!stack) {
		perror("stack malloc");
		return -1;
	}
	stack += PTHREAD_STACK_MIN;

	pid_set.target_pids = &pid;
	pid_set.num_pids = 1;

	if (child->flags & TASK_THREAD) {
		flags |= CLONE_THREAD | CLONE_SIGHAND | CLONE_VM;
	} else if (child->flags & TASK_SIBLING) {
		flags |= CLONE_PARENT;
	}

	/* select pid if --pids, otherwise it's 0 */
	if (ctx->args->pids)
		pid = child->pid;

#ifdef CLONE_NEWPID
	/* but for new pidns, don't specify a pid */
 	if (child->flags & TASK_NEWPID) {
		flags |= CLONE_NEWPID;
		pid = 0;
	}
#endif

	global_parent_pid = _getpid();

	pid = clone_with_pids(ckpt_fork_stub, stack, flags, &pid_set, child);
	if (pid < 0) {
		perror("clone");
		free(stack - PTHREAD_STACK_MIN);
		return -1;
	}

	if (!(child->flags & TASK_THREAD))
		free(stack - PTHREAD_STACK_MIN);

	ckpt_dbg("forked child vpid %d (asked %d)\n", pid, child->pid);
	return pid;
}

/*
 * ckpt_fork_feeder: create the feeder process and set a pipe to deliver
 * the feeder's stdout to our stdin.
 *
 * Also setup another pipe through which new tasks will report their
 * old- and new-pid (see ckpt_adjust_pids). This was originally used
 * only for '--no-pids', but now also ensures that all restarting
 * tasks are created by the time coordinator calls restart(2).
 */
static int ckpt_fork_feeder(struct ckpt_ctx *ctx)
{
	void *stack;
	pid_t pid;

	if (pipe(ctx->pipe_feed)) {
		perror("pipe");
		exit(1);
	}

	if (pipe(ctx->pipe_child) < 0) {
		perror("pipe");
		exit(1);
	}

	/*
	 * Use clone() without SIGCHLD so that the when the feeder
	 * terminates it does not notify the parent (coordinator), as
	 * this may interfere with the restart.
	 */

	stack = malloc(PTHREAD_STACK_MIN);
	if (!stack) {
		perror("stack malloc");
		return -1;
	}
	stack += PTHREAD_STACK_MIN;

	pid = clone(ckpt_do_feeder, stack,
		    CLONE_THREAD | CLONE_SIGHAND | CLONE_VM, ctx);
	if (pid < 0) {
		perror("feeder thread");
		return -1;
	}

	/* children pipe */
	close(ctx->pipe_child[0]);
	ctx->pipe_out = ctx->pipe_child[1];
	/* feeder pipe */
	close(ctx->pipe_feed[1]);
	if (ctx->pipe_feed[0] != STDIN_FILENO) {
		dup2(ctx->pipe_feed[0], STDIN_FILENO);
		close(ctx->pipe_feed[0]);
	}

	return 0;
}

static void ckpt_abort(struct ckpt_ctx *ctx, char *str)
{
	perror(str);
	kill(-(ctx->init_pid), SIGKILL);
	exit(1);
}

/*
 * feeder process: delegates checkpoint image stream to the kernel.
 * In '--no-pids' mode, transform the pids array (struct ckpt_hdr_pids)
 * on the fly and feed the result to the "init" task of the restart
 */
static int ckpt_do_feeder(void *data)
{
	struct ckpt_ctx *ctx = (struct ckpt_ctx *) data;
	int ret;

	/* children pipe */
	close(ctx->pipe_child[1]);
	ctx->pipe_in = ctx->pipe_child[0];
	/* feeder pipe */
	close(ctx->pipe_feed[0]);
	if (ctx->pipe_feed[1] != STDOUT_FILENO) {
		dup2(ctx->pipe_feed[1], STDOUT_FILENO);
		close(ctx->pipe_feed[1]);
	}

	if (ckpt_adjust_pids(ctx) < 0)
		ckpt_abort(ctx, "collect pids");

	if (ckpt_write_header(ctx) < 0)
		ckpt_abort(ctx, "write c/r header");

	if (ckpt_write_header_arch(ctx) < 0)
		ckpt_abort(ctx, "write c/r header arch");

	if (ckpt_write_tree(ctx) < 0)
		ckpt_abort(ctx, "write c/r tree");

	/* read rest -> write rest */
	while (1) {
		ret = read(STDIN_FILENO, ctx->buf, BUFSIZE);
		ckpt_dbg("c/r read input %d\n", ret);
		if (ret == 0)
			break;
		if (ret < 0)
			ckpt_abort(ctx, "read input");
		ret = ckpt_write(STDOUT_FILENO, ctx->buf, ret);
		if (ret < 0)
			ckpt_abort(ctx, "write output");
	}

	/* all is well: feeder thread is done */
	return 0;
}

/*
 * ckpt_adjust_pids: transform the pids array (struct ckpt_hdr_pids) by
 * substituing actual pid values for original pid values.
 *
 * Collect pids reported by the newly created tasks; each task sends
 * a 'struct pid_swap' indicating old- and new-pid. Then modify the
 * the pids array accordingly.
 */
static int ckpt_adjust_pids(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr_pids *copy_arr;
	struct pid_swap swap;
	int n, m, copy_len, ret;

	/*
	 * Make a copy of the original array to fix a nifty bug where
	 * two tasks in original image with pids A, B, restart with
	 * pids swapped (B and A), for instance -
	 *    original pid array:    [][][A][][B][]...
	 *    first, swap B with A:  [][][A][][A][]...
	 *    then, swap A with B:   [][][B][][B][]...
	 *    but correct should be: [][][B][][A][]...
	 */

	copy_len = sizeof(*copy_arr) * ctx->pids_nr;
	copy_arr = malloc(copy_len);
	if (!copy_arr)
		ckpt_abort(ctx, "malloc copy pids");
	memcpy(copy_arr, ctx->pids_arr, copy_len);

	/* read in 'pid_swap' data and adjust ctx->pids_arr */
	for (n = 0; n < ctx->pids_nr; n++) {
		ret = read(ctx->pipe_in, &swap, sizeof(swap));
		if (ret < 0) {
			free(copy_arr);
			ckpt_abort(ctx, "read pipe");
		}

		/* swapping isn't needed with '--pids' */
		if (ctx->args->pids)
			continue;

		ckpt_dbg("c/r swap old %d new %d\n", swap.old, swap.new);
		for (m = 0; m < ctx->pids_nr; m++) {
			if (ctx->pids_arr[m].vpid == swap.old)
				copy_arr[m].vpid = swap.new;
			if (ctx->pids_arr[m].vtgid == swap.old)
				copy_arr[m].vtgid = swap.new;
			if (ctx->pids_arr[m].vppid == swap.old)
				copy_arr[m].vppid = swap.new;
		}
	}

	memcpy(ctx->pids_arr, copy_arr, copy_len);

	close(ctx->pipe_in);
	free(copy_arr);
	return 0;
}

/*
 * low-level write
 *   ckpt_write - write 'count' bytes to 'buf'
 *   ckpt_write_obj - write object
 *   ckpt_write_obj_buffer - write buffer object
 */
static int ckpt_write(int fd, void *buf, int count)
{
	ssize_t nwrite;
	int nleft;

	for (nleft = count; nleft; nleft -= nwrite) {
		nwrite = write(fd, buf, nleft);
		if (nwrite < 0 && errno == EAGAIN)
			continue;
		if (nwrite < 0)
			return -1;
		buf += nwrite;
	}
	return 0;
}

int ckpt_write_obj(struct ckpt_ctx *ctx, struct ckpt_hdr *h)
{
	return ckpt_write(STDOUT_FILENO, h, h->len);
}

int ckpt_write_obj_ptr(struct ckpt_ctx *ctx, void *buf, int n, int type)
{
	struct ckpt_hdr h;
	int ret;

	h.type = type;
	h.len = n + sizeof(h);
	ret = ckpt_write(STDOUT_FILENO, &h, sizeof(h));
	if (!ret)
		ret = ckpt_write(STDOUT_FILENO, buf, n);
	return ret;
}

/*
 * low-level read
 *   ckpt_read - read 'count' bytes to 'buf'
 *   ckpt_read_obj - read up to 'n' bytes of object into 'buf'
 *   ckpt_read_obj_type - read up to 'n' bytes of object type 'type' into 'buf'
 *   ckpt_read_obj_ptr - like ckpt_read_obj_type, but discards header
 */
static int ckpt_read(int fd, void *buf, int count)
{
	ssize_t nread;
	int nleft;

	for (nleft = count; nleft; nleft -= nread) {
		nread = read(fd, buf, nleft);
		if (nread < 0 && errno == EAGAIN)
			continue;
		if (nread <= 0)
			return -1;
		buf += nread;
	}
	return 0;
}

static int ckpt_read_obj(struct ckpt_ctx *ctx,
			 struct ckpt_hdr *h, void *buf, int n)
{
	int ret;

	ret = ckpt_read(STDIN_FILENO, h, sizeof(*h));
	if (ret < 0)
		return ret;
	if (h->len > n) {
		errno = EINVAL;
		return -1;
	}
	return ckpt_read(STDIN_FILENO, buf, h->len - sizeof(*h));
}

static int ckpt_read_obj_type(struct ckpt_ctx *ctx, void *buf, int n, int type)
{
	struct ckpt_hdr *h = (struct ckpt_hdr *) buf;
	int ret;

	ret = ckpt_read_obj(ctx, h, (void *) (h + 1), n);
	if (ret < 0)
		return ret;
	if (h->type != type) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

static int ckpt_read_obj_ptr(struct ckpt_ctx *ctx, void *buf, int n, int type)
{
	struct ckpt_hdr h;
	int ret;

	ret = ckpt_read_obj(ctx, &h, buf, n + sizeof(h));
	if (ret < 0)
		return ret;
	if (h.type != type) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

static int ckpt_read_obj_buffer(struct ckpt_ctx *ctx, void *buf, int n)
{
	return ckpt_read_obj_type(ctx, buf, BUFSIZE, CKPT_HDR_BUFFER);
}

/*
 * read/write the checkpoint image: similar to in-kernel code
 */

static int ckpt_read_header(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr_header *h;
	char *ptr;
	int ret;

	h = (struct ckpt_hdr_header *) ctx->header;
	ret = ckpt_read_obj_type(ctx, h, sizeof(*h), CKPT_HDR_HEADER);
	if (ret < 0)
		return ret;

	if (h->constants.uts_release_len > BUFSIZE / 4 ||
	    h->constants.uts_version_len > BUFSIZE / 4 ||
	    h->constants.uts_machine_len > BUFSIZE / 4) {
		errno = EINVAL;
		return -1;
	}

	ptr = (char *) h;

	ptr += ((struct ckpt_hdr *) ptr)->len;
	ret = ckpt_read_obj_buffer(ctx, ptr, h->constants.uts_release_len);
	if (ret < 0)
		return ret;
	ptr += ((struct ckpt_hdr *) ptr)->len;
	ret = ckpt_read_obj_buffer(ctx, ptr, h->constants.uts_version_len);
	if (ret < 0)
		return ret;
	ptr += ((struct ckpt_hdr *) ptr)->len;
	ret = ckpt_read_obj_buffer(ctx, ptr, h->constants.uts_machine_len);
	if (ret < 0)
		return ret;

	/* FIXME: skip version validation for now */

	return 0;
}

static int ckpt_read_header_arch(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr_header_arch *h;
	int ret;

	h = (struct ckpt_hdr_header_arch *) ctx->header_arch;
	ret = ckpt_read_obj_type(ctx, h, sizeof(*h), CKPT_HDR_HEADER_ARCH);
	if (ret < 0)
		return ret;

	return 0;
}

static int ckpt_read_tree(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr_tree *h;
	int len, ret;

	h = (struct ckpt_hdr_tree *) ctx->tree;
	ret = ckpt_read_obj_type(ctx, h, sizeof(*h), CKPT_HDR_TREE);
	if (ret < 0)
		return ret;

	ckpt_dbg("number of tasks: %d\n", h->nr_tasks);

	if (h->nr_tasks <= 0) {
		ckpt_err("invalid number of tasks %d", h->nr_tasks);
		errno = EINVAL;
		return -1;
	}

	/* get a working a copy of header */
	memcpy(ctx->buf, ctx->tree, BUFSIZE);

	len = sizeof(struct ckpt_hdr_pids) * h->nr_tasks;

	ctx->pids_nr = h->nr_tasks;
	ctx->pids_arr = malloc(len);
	if (!ctx->pids_arr)
		return -1;

	ret = ckpt_read_obj_ptr(ctx, ctx->pids_arr, len, CKPT_HDR_BUFFER);
	if (ret < 0)
		free(ctx->pids_arr);

	return ret;
}

static int ckpt_write_header(struct ckpt_ctx *ctx)
{
	char *ptr;
	int ret;

	ptr = (char *) ctx->header;
	ret = ckpt_write_obj(ctx, (struct ckpt_hdr *) ptr);
	if (ret < 0)
		return ret;

	ptr += ((struct ckpt_hdr *) ptr)->len;
	ret = ckpt_write_obj(ctx, (struct ckpt_hdr *) ptr);
	if (ret < 0)
		return ret;
	ptr += ((struct ckpt_hdr *) ptr)->len;
	ret = ckpt_write_obj(ctx, (struct ckpt_hdr *) ptr);
	if (ret < 0)
		return ret;
	ptr += ((struct ckpt_hdr *) ptr)->len;
	ret = ckpt_write_obj(ctx, (struct ckpt_hdr *) ptr);

	return ret;
}

static int ckpt_write_header_arch(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr_header_arch *h;

	h = (struct ckpt_hdr_header_arch *) ctx->header_arch;
	return ckpt_write_obj(ctx, (struct ckpt_hdr *) h);
}

static int ckpt_write_tree(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr_tree *h;
	int len;

	h = (struct ckpt_hdr_tree *) ctx->tree;
	if (ckpt_write_obj(ctx, (struct ckpt_hdr *) h) < 0)
		ckpt_abort(ctx, "write tree");

	len = sizeof(struct ckpt_hdr_pids) * ctx->pids_nr;
	if (ckpt_write_obj_ptr(ctx, ctx->pids_arr, len, CKPT_HDR_BUFFER) < 0)
		ckpt_abort(ctx, "write pids");

	return 0;
}

/*
 * libc doesn't support clone_with_pid() yet...
 * below is arch-dependent code to use the syscall
 */
#if defined(__i386__) && defined(__NR_clone_with_pids)

/*
 * x86_32
 * (see: http://lkml.indiana.edu/hypermail/linux/kernel/9604.3/0204.html)
 */
static int clone_with_pids(int (*fn)(void *), void *child_stack, int flags,
			   struct target_pid_set *target_pids, void *arg)
{
	long retval;
	void **newstack;

	/*
	 * Set up the stack for child:
	 *  - the (void *) arg will be the argument for the child function
	 *  - the fn pointer will be loaded into ebx after the clone
	 */
	newstack = (void **) child_stack;
	*--newstack = arg;
	*--newstack = fn;

	__asm__  __volatile__(
		 "movl %0, %%ebx\n\t"		/* flags -> 1st (ebx) */
		 "movl %1, %%ecx\n\t"		/* newstack -> 2nd (ecx)*/
		 "xorl %%edi, %%edi\n\t"	/* 0 -> 3rd (edi) */
		 "xorl %%edx, %%edx\n\t"	/* 0 -> 4th (edx) */
		 "pushl %%ebp\n\t"		/* save value of ebp */
		 "movl %2, %%ebp\n\t"		/* flags -> 6th (ebp) */
		:
		:"b" (flags),
		 "c" (newstack),
		 "r" (target_pids)
		);

	__asm__ __volatile__(
		 "int $0x80\n\t"	/* Linux/i386 system call */
		 "testl %0,%0\n\t"	/* check return value */
		 "jne 1f\n\t"		/* jump if parent */
		 "popl %%ebx\n\t"	/* get subthread function */
		 "call *%%ebx\n\t"	/* start subthread function */
		 "movl %2,%0\n\t"
		 "int $0x80\n"		/* exit system call: exit subthread */
		 "1:\n\t"
		 "popl %%ebp\t"		/* restore parent's ebp */
		:"=a" (retval)
		:"0" (__NR_clone_with_pids), "i" (__NR_exit)
		:"ebx", "ecx"
		);

	if (retval < 0) {
		errno = -retval;
		retval = -1;
	}
	return retval;
}

#elif defined(__s390__) && defined(__NR_clone_with_pids)

/*
 * s390
 */
#define do_clone_with_pids(stack, flags, ptid, ctid, setp) ({ \
	register unsigned long int __r2 asm ("2") = (unsigned long int)(stack);\
	register unsigned long int __r3 asm ("3") = (unsigned long int)(flags);\
	register unsigned long int __r4 asm ("4") = (unsigned long int)(ptid); \
	register unsigned long int __r5 asm ("5") = (unsigned long int)(ctid); \
	register unsigned long int __r6 asm ("6") = (unsigned long int)(NULL); \
	register unsigned long int __r7 asm ("7") = (unsigned long int)(setp); \
	register unsigned long int __result asm ("2"); \
	__asm__ __volatile__( \
		" lghi %%r1,%7\n" \
		" svc 0\n" \
		: "=d" (__result) \
		: "0" (__r2), "d" (__r3), \
		  "d" (__r4), "d" (__r5), "d" (__r6), "d" (__r7), \
		  "i" (__NR_clone_with_pids) \
		: "1", "cc", "memory" \
	); \
		__result; \
	})

int clone_with_pids(int (*fn)(void *), void *child_stack, int flags,
			struct target_pid_set *target_pids, void *arg)
{
	long retval;
	retval = do_clone_with_pids(child_stack, flags, NULL, NULL,
				    target_pids);

	if (retval < 0) {
		errno = -retval;
		return -1;
	} else if (retval == 0) {
		return fn(arg);
	} else
		return retval;
}

#else  /* !defined(__NR_clone_with_pids) */

/* on other architectures fallback to regular clone(2) */
static int clone_with_pids(int (*fn)(void *), void *child_stack, int flags,
			   struct target_pid_set *target_pids, void *arg)
{
	return clone(fn, child_stack, flags, arg);
}

#endif

/*
 * a simple hash implementation
 */

#define HASH_BITS	11
#define HASH_BUCKETS	(2 << (HASH_BITS - 1))

static int hash_init(struct ckpt_ctx *ctx)
{
	struct hashent **hash;

	ctx->hash_arr = malloc(sizeof(*hash) * HASH_BUCKETS);
	if (!ctx->hash_arr) {
		perror("malloc hash table");
		return -1;
	}
	memset(ctx->hash_arr, 0, sizeof(*hash) * HASH_BUCKETS);
	return 0;
}

static void hash_exit(struct ckpt_ctx *ctx)
{
	struct hashent *hash, *next;
	int i;

	for (i = 0; i < HASH_BUCKETS; i++) {
		for (hash = ctx->hash_arr[i]; hash; hash = next) {
			next = hash->next;
			free(hash);
		}
	}

	free(ctx->hash_arr);
}

/* see linux kernel's include/linux/hash.h */

/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME_32 0x9e370001UL

static inline int hash_func(long key)
{
	unsigned long hash = key * GOLDEN_RATIO_PRIME_32;
	return (hash >> (sizeof(key)*8 - HASH_BITS));
}

static int hash_insert(struct ckpt_ctx *ctx, long key, void *data)
{
	struct hashent *hash;
	int bucket;

	hash = malloc(sizeof(*hash));
	if (!hash) {
		perror("malloc hash");
		return -1;
	}
	hash->key = key;
	hash->data = data;

	bucket = hash_func(key);
	hash->next = ctx->hash_arr[bucket];
	ctx->hash_arr[bucket] = hash;

	return 0;
}

static void *hash_lookup(struct ckpt_ctx *ctx, long key)
{
	struct hashent *hash;
	int bucket;

	bucket = hash_func(key);
	for (hash = ctx->hash_arr[bucket]; hash; hash = hash->next) {
		if (hash->key == key)
			return hash->data;
	}
	return NULL;
}
