/*
 *  restart.c: restart process(es) from a checkpoint
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
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <stdarg.h>
#include <assert.h>

#include <linux/checkpoint.h>
#include <linux/checkpoint_hdr.h>

#include "eclone.h"
#include "genstack.h"
#include "compat.h"
#include "checkpoint.h"
#include "common.h"

/*
 * To re-create the tasks tree in user space, 'restart' reads the
 * header and tree data from the checkpoint image tree. It makes up
 * for the data that was consumed by using a helper process that
 * provides the data back to the restart syscall, followed by the rest
 * of the checkpoint image stream.
 *
 * By default, 'restart' creates a new pid namespace in which the
 * restart takes place, using the original pids from the time of the
 * checkpoint. This requires that CLONE_NEWPID and eclone() be enabled.
 *
 * Restart can also occur in the current namespace, however pids from
 * the time of the checkpoint may be already in use then. Therefore,
 * by default, 'restart' creates an equivalen tree without restoring
 * the original pids, assuming that the application can tolerate this.
 * For this, the 'ckpt_pids' array is transformed on-the-fly before it
 * is fed to the kernel. This mode of operation is permitted only if
 * all the restarting tasks belong to a single pid-namespace (i.e. no
 * pid-namespace nesting).
 *
 * By default, "--pids" implies "--pidns" and vice-versa. The user can
 * use "--pids --no-pidns" for a restart in the currnet namespace -
 * 'restart' will attempt to create the new tree with the original pids
 * from the time of the checkpoint, if possible. This requires that
 * eclone() be enabled.
 */

struct hashent {
	long key;
	void *data;
	struct hashent *next;
};

struct task;
struct ckpt_ctx;

/*
 * The following data structres are used to track pids:
 *
 * ctx->pids_arr[]:
 *   Array of (variable sized) 'struct ckpt_pids' from the checkpoint
 *   image, each entry indicates the level (depth) relative to the
 *   root task, and the pids at each level. NOTE: the order of pids
 *   matches order of adding them to the objhash during checkpoint
 *   (hence their tags).
 *
 * ctx->pids_copy[]:
 *   Array used to hold a copy of pids_arr[] during --no-pids restart
 *   when converting the task's pids from the original values from
 *   the checkpoint image, to the real pids produced by forks.
 *
 * ctx->pids_new[]:
 *   Array of (variable sized) 'struct ckpt_pids' to hold new pids
 *   objects allocated by the MakeForst algorithm fo the restart.
 *
 * ctx->pids_index[]:
 *   Array of integers that provides mapping from a pid object (tag)
 *   to the byte offset inside ctx->pids_arr where that pid object
 *   is. It is useful since the entries in the latter are of variable
 *   size.
 *
 * ctx->tasks_arr[]:
 *   Array of 'struct ckpt_task_pids' from the checkpoint image, each
 *   entry indicates a task's pids (pid,tgid,pgid,sid,ppid) and the
 *   pid-namespace nesting level. NOTE: the pids store the tags of the
 *   corresponding pid objects (and thus their order in ctx->pids_arr)
 *   rather then the pid values themselves.
 *
 * ctx->tasks[]:
 *   Array of 'struct task' that holds information about all the tasks
 *   neede to be created in userespace (the input and output of the
 *   DumpForst and CreateForest algorithms). NOTE: the pids here also
 *   store the tags of the corresponding pid objects).
 *
 * When restart algorithm needs to create dead tasks or produce dummy
 * tasks, it stores new 'ckpt_pids' objects in ctx->pids_new[], and
 * extends ctx->pids[] and ctx->tasks[] to store index to new pids
 * and new tasks, respectively.
 *
 * ctx->pids_nr:  (original) size of ctx->pids_arr
 * ctx->pids_cnt: current size of ctx->pids_index
 * ctx->pids_max: maximum size of ctx->pids_index
 * ctx->pids_off: current offset in ctx->pids_new[]
 * ctx->pids_len: maximum offset in ctx->pids_new[]
 *
 * ctx->tasks_nr:  size of ctx->pids_arr
 * ctx->tasks_cnt: current size of ctx->tasks
 * ctx->tasks_max: maximum size of ctx->tasks
 *
 * Given a byte offset in ctx->pids_arr, to get the 'ckpt_pids':
 *   pids = pid_at_index(ctx, @offset)
 *
 * Given a pid-index from ctx->tasks/ctx->tasks_arr, to get the byte
 * offset of the matching 'ckpt_pids' in ctx->pids_arr:
 *   ctx->pids_index[@index]
 *
 * And to get the 'ckpt_pids' from an index:
 *   pids = pids_of_index(@index)
 *
 *
 * ctx->tasks_pids[]:
 *   Array of pid values indicating the next hint for pid allocation
 *   at each nesting level of pid-namespace.
 */

struct task {
	int flags;		/* state and (later) actions */

	struct task *children;	/* pointers to first child, next and prev */
	struct task *next_sib;	/*   sibling, and the creator of a process */
	struct task *prev_sib;
	struct task *creator;

	struct task *phantom;	/* pointer to place-holdler task (if any) */

	int vidx;		/* index into vpid array, -1 if none */
	int piddepth;

	/* Following are INDEX values into ctx->pids_index */
	int pid_ind;		/* process IDs, our bread-&-butter */
	int ppid_ind;
	int tgid_ind;
	int sid_ind;
	
	struct ckpt_ctx *ctx;	/* points back to the c/r context */

	pid_t real_parent;	/* pid of task's real parent */
};

/* zero_task represents creator of root_task (all pids 0) */
struct task zero_task;

#define TASK_ROOT	0x1	/* root task */
#define TASK_GHOST	0x2	/* dead task (pid used as sid/pgid) */
#define TASK_THREAD	0x4	/* thread (non leader) */
#define TASK_SIBLING	0x8	/* creator's sibling (use CLONE_PARENT) */
#define TASK_SESSION	0x10	/* inherits creator's original sid */
#define TASK_NEWPID	0x20	/* starts a new pid namespace */
#define TASK_DEAD	0x40	/* dead task (dummy) */
#define TASK_NEWROOT	0x80	/* task must chroot() */
#define TASK_NEWPTS	0x100	/* remount devpts */
#define TASK_NEWNS	0x200	/* unshare namespace/file-system */

struct ckpt_ctx {

	enum {
		CTX_FEEDER,
		CTX_RESTART,
	} whoami;

	int error;
	int success;
	int printed;

	int pipe_in;
	int pipe_out;

	int pipe_child[2];	/* for children to report status */
	int pipe_feed[2];	/* for feeder to provide input */
	int pipe_coord[2];	/* for coord to report status (if needed) */

	int root_pid;
	int pid_offset;

	struct ckpt_pids *pids_arr;
	struct ckpt_pids *pids_new;
	struct ckpt_pids *pids_copy;
	int *pids_index;

	int pids_nr;
	int vpids_nr;
	int pids_cnt;
	int pids_max;
	int pids_off;
	int pids_len;

	struct ckpt_task_pids *tasks_arr;
	struct task *tasks;

	int tasks_nr;
	int tasks_cnt;
	int tasks_max;

	/* an array of pid hash-tables: one hash-table per pidns level */
	struct hashent ***hash_arr;
	int *hash_last_pid;
	int hash_depth;
	
	char header[BUFSIZE];
	char header_arch[BUFSIZE];
	char container[BUFSIZE];
	char tree[BUFSIZE];
	char pids[BUFSIZE];
	char buf[BUFSIZE];

	struct cr_restart_args *args;

	char *freezer;

	/* system limits */
	pid_t pid_max;
};

struct pid_swap {
	pid_t old;
	pid_t new;
};

#define CKPT_RESERVED_PIDS 300  /* in the spirit of kernel/pid.c */

/*
 * TODO: Do we need to direct user-space restart messages to two different
 * 	 fds (like stdout and stderr) or can we just use one ?
 */
static int global_ulogfd;
static int global_uerrfd;
static int global_debug;
static int global_verbose;
static pid_t global_feeder_pid;
static pid_t global_child_pid;
static int global_child_status;
static int global_child_collected;
static int global_sent_sigint;
static struct signal_array signal_array[] = INIT_SIGNAL_ARRAY;

/*
 * TODO: Implement an API to let callers choose if/how an interrupt be sent
 * 	 and remove global_send_sigint.
 */
int global_send_sigint = -1;

static int ckpt_remount_proc(struct ckpt_ctx *ctx);
static int ckpt_remount_devpts(struct ckpt_ctx *ctx);

static int ckpt_build_pids(struct ckpt_ctx *ctx);
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
static int ckpt_do_feeder(struct ckpt_ctx *ctx);
static int ckpt_fork_feeder(struct ckpt_ctx *ctx);

static int ckpt_write(int fd, void *buf, int count);
static int ckpt_write_obj(struct ckpt_ctx *ctx, struct ckpt_hdr *h);

static int ckpt_write_header(struct ckpt_ctx *ctx);
static int ckpt_write_header_arch(struct ckpt_ctx *ctx);
static int ckpt_write_container(struct ckpt_ctx *ctx);
static int ckpt_write_pids(struct ckpt_ctx *ctx);
static int ckpt_write_tree(struct ckpt_ctx *ctx);

static int _ckpt_read(int fd, void *buf, int count);
static int ckpt_read(int fd, void *buf, int count);
static int ckpt_read_obj(struct ckpt_ctx *ctx,
			 struct ckpt_hdr *h, void *buf, int n);
static int ckpt_read_obj_type(struct ckpt_ctx *ctx, void *b, int n, int type);

static int ckpt_read_header(struct ckpt_ctx *ctx);
static int ckpt_read_header_arch(struct ckpt_ctx *ctx);
static int ckpt_read_container(struct ckpt_ctx *ctx);
static int ckpt_read_tree(struct ckpt_ctx *ctx);
static int ckpt_read_pids(struct ckpt_ctx *ctx);

static int hash_init(struct ckpt_ctx *ctx);
static void hash_exit(struct ckpt_ctx *ctx);
static void *hash_lookup(struct ckpt_ctx *ctx, long key);
static void *hash_lookup_level(struct ckpt_ctx *ctx, long key, int level);
static void *hash_lookup_ind(struct ckpt_ctx *ctx, int n);
static int hash_insert(struct ckpt_ctx *ctx, long key, void *data, int level);

static inline pid_t _gettid(void)
{
	return syscall(__NR_gettid);
}

static inline pid_t _getpid(void)
{
	return syscall(__NR_getpid);
}

static inline int restart(pid_t pid, int fd, unsigned long flags, int klogfd)
{
	return syscall(__NR_restart, pid, fd, flags, klogfd);
}

static inline int ckpt_cond_warn(struct ckpt_ctx *ctx, long mask)
{
	return (ctx->args->warn & mask);
}
		
static inline int ckpt_cond_fail(struct ckpt_ctx *ctx, long mask)
{
	return (ctx->args->fail & mask);
}

static inline int ctx_set_errno(struct ckpt_ctx *ctx)
{
	if (!ctx->error)
		ctx->error = errno;
	return -1;
}

static inline int ctx_ret_errno(struct ckpt_ctx *ctx, int err)
{
	if (!ctx->error)
		ctx->error = err;
	return -1;
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

static char *sig2str(int sig)
{
	int i = 0;

	do {
		if (signal_array[i].signum == sig)
			return signal_array[i].sigstr;
	} while (signal_array[++i].signum >= 0);
	return "UNKNOWN SIGNAL";
}

static void sigusr1_handler(int sig)
{
	ckpt_dbg("SIGUSER1: restarting process would become orphan.\n");
	exit(1);
}

static void sigsegv_handler(int sig)
{
	ckpt_dbg("SIGSEGV: restarting process unexpected fault.\n");
	exit(1);
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
			/* inform collection of coordinator or root-task */
			if (pid == global_child_pid) {
				global_child_status = status;
				global_child_collected = 1;
				ckpt_dbg("collected coord/root task\n");
				report_exit_status(status, "SIGCHLD:", 1);
			}
			/* collect the feeder child */
			if (pid == global_feeder_pid) {
				ckpt_dbg("collected feeder process\n");
				report_exit_status(status, "SIGCHLD:", 1);
			}
			ckpt_dbg("SIGCHLD: collected child %d\n", pid);
			collected = 1;
		} else if (errno == EINTR) {
			ckpt_dbg("SIGCHLD: waitpid interrupted\n");
		} else if (errno == ECHILD) {
			break;
		} else {
			ckpt_perror("WEIRD !! child collection failed");
			exit(1);
		}
	}

	if (!collected)
		ckpt_dbg("SIGCHLD: already collected\n");
}

static void sigint_handler(int sig)
{
	pid_t pid = global_child_pid;

	sig = global_send_sigint;
	if (!sig) {
		ckpt_verbose("Interrupt attempt .. ignored.\n");
		return;
	}

	ckpt_verbose("Interrupted: sent SIG%s to "
		     "restarted tasks\n", sig2str(sig));

	if (pid) {
		ckpt_dbg("delegating SIG%s to child %d "
			 "(coordinator/root task)\n",
			 sig2str(sig), pid);
		kill(-pid, sig);
		kill(pid, sig);
	}
}

static int freezer_prepare(struct ckpt_ctx *ctx)
{
	int fd, ret;

#define FREEZER_THAWED  "THAWED"

	ctx->freezer = malloc(strlen(ctx->args->freezer) + 32);
	if (!ctx->freezer) {
		ckpt_perror("malloc freezer buf");
		return ctx_set_errno(ctx);
	}

	sprintf(ctx->freezer, "%s/freezer.state", ctx->args->freezer);

	fd = open(ctx->freezer, O_WRONLY, 0);
	if (fd < 0) {
		ckpt_perror("freezer path");
		return ctx_set_errno(ctx);
	}
	ret = write(fd, FREEZER_THAWED, sizeof(FREEZER_THAWED)); 
	if (ret != sizeof(FREEZER_THAWED)) {
		ckpt_perror("thawing freezer");
		ctx_set_errno(ctx);
		close(fd);
		return -1;
	}

	sprintf(ctx->freezer, "%s/tasks", ctx->args->freezer);
	close(fd);
	return 0;
}

static int freezer_register(struct ckpt_ctx *ctx, pid_t pid)
{
	char pidstr[16];
	int fd, n, ret;

	fd = open(ctx->freezer, O_WRONLY, 0);
	if (fd < 0) {
		ckpt_perror("freezer path");
		return ctx_set_errno(ctx);
	}

	n = sprintf(pidstr, "%d", pid);
	ret = write(fd, pidstr, n);
	if (ret != n) {
		ckpt_perror("adding pid %d to freezer");
		ctx_set_errno(ctx);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

/*
 * Validate the specified arguments and initialize globals based on the
 * arguments. Return 0 on success.
 */
int process_args(struct cr_restart_args *args)
{
	global_debug = args->debug;
	global_verbose = args->verbose;
	global_ulogfd = args->ulogfd;
	global_uerrfd = args->uerrfd;

	if (args->infd < 0) {
		ckpt_err("Invalid input fd %d\n", args->infd);
		return -1;
	}

	/* output file descriptor (default: none) */
	if (args->klogfd < 0)
		args->klogfd = CHECKPOINT_FD_NONE;

	if (args->mnt_pty)
		args->mntns = 1;

#ifndef CLONE_NEWPID
	if (args->pidns) {
		ckpt_err("This version of restart was compiled without "
		       "support for --pidns.\n");
		errno = ENOSYS;
		return -1;
	}
#endif

#ifndef CHECKPOINT_DEBUG
	if (global_debug) {
		ckpt_err("This version of restart was compiled without "
		       "support for --debug.\n");
		errno = ENOSYS;
		return -1;
	}
#endif

	if (args->pidns)
		args->pids = 1;

#if 0   /* Defered until __NR_eclone makes it to standard headers */
#ifndef __NR_eclone
	if (args->pids) {
		ckpt_err("This version of restart was compiled without "
		       "support for --pids.\n");
		errno = ENOSYS;
		return -1;
	}
#endif
#endif

	if (args->self &&
	    (args->pids || args->pidns || args->show_status ||
	     args->copy_status || args->freezer)) {
		ckpt_err("Invalid mix of --self with multiprocess options\n");
		errno = EINVAL;
		return -1;
	}

	return 0;
}

static void init_ctx(struct ckpt_ctx *ctx)
{
	FILE *file;
	char buf[1024];

	memset(ctx, 0, sizeof(*ctx));

	/* mark all fds as unused */
	ctx->pipe_in = -1;
	ctx->pipe_out = -1;
	ctx->pipe_child[0] = -1;
	ctx->pipe_child[1] = -1;
	ctx->pipe_feed[0] = -1;
	ctx->pipe_feed[1] = -1;
	ctx->pipe_coord[0] = -1;
	ctx->pipe_coord[1] = -1;

	/* system limits */
	ctx->pid_max = SHRT_MAX;  /* default */
	file = fopen("/proc/sys/kernel/pid_max", "r");
	if (file) {
		if (fgets(buf, 1024, file))
			ctx->pid_max = atoi(buf);
		fclose(file);
	}
}

static void exit_ctx(struct ckpt_ctx *ctx)
{
	if (ctx->freezer)
		free(ctx->freezer);

	if (ctx->tasks)
		free(ctx->tasks);
	if (ctx->tasks_arr)
		free(ctx->tasks_arr);

	if (ctx->pids_index)
		free(ctx->pids_index);
	if (ctx->pids_arr)
		free(ctx->pids_arr);
	if (ctx->pids_new)
		free(ctx->pids_new);
	if (ctx->pids_copy)
		free(ctx->pids_copy);

	/* unused fd will be silently ignored */
	close(ctx->pipe_in);
	close(ctx->pipe_out);
	close(ctx->pipe_child[0]);
	close(ctx->pipe_child[1]);
	close(ctx->pipe_feed[0]);
	close(ctx->pipe_feed[1]);
	close(ctx->pipe_coord[0]);
	close(ctx->pipe_coord[1]);
}

static inline struct task *ckpt_init_task(struct ckpt_ctx *ctx)
{
	return &ctx->tasks[0];
}

static inline struct ckpt_pids *pids_at_offset(struct ckpt_ctx *ctx, int n)
{
	return (struct ckpt_pids *)(((char *) ctx->pids_arr) + n);
}

static inline struct ckpt_pids *pids_copy_at_offset(struct ckpt_ctx *ctx, int n)
{
	return (struct ckpt_pids *)(((char *) ctx->pids_copy) + n);
}

static inline struct ckpt_pids *pids_new_at_offset(struct ckpt_ctx *ctx, int n)
{
	return (struct ckpt_pids *)(((char *) ctx->pids_new) + n);
}

struct ckpt_pids pids_zero = {
	.depth = 0,
	.numbers = {0},
};

struct ckpt_pids pids_root = {
	.depth = 0,
	.numbers = {-1},
};

static inline struct ckpt_pids *pids_of_index(struct ckpt_ctx *ctx, int n)
{
	if (n == 0)
		return &pids_zero;
	else if (n == CKPT_PID_ROOT)
		return &pids_root;
	if (n < 0 || n > ctx->pids_cnt) {
		errno = EINVAL;
		return NULL;
	}
	if (n <= ctx->pids_nr)
		return pids_at_offset(ctx, ctx->pids_index[n]);
	else
		return pids_new_at_offset(ctx, ctx->pids_index[n]);
}

static inline pid_t pid_at_index(struct ckpt_ctx *ctx, int n)
{
	return pids_of_index(ctx, n)->numbers[0];
}

static void verbose_status(struct ckpt_ctx *ctx)
{
	if (ctx->printed)
		return;

	if (ctx->error)
		errno = ctx->error;

	if (ctx->success) {
		ckpt_dbg("c/r succeeded\n");
		ckpt_verbose("Restart succeeded\n");
	} else {
		ckpt_dbg("c/r failed ?\n");
		ckpt_perror("restart");
		ckpt_verbose("Restart failed\n");
	}

	ctx->printed = 1;
}


int cr_restart(struct cr_restart_args *args)
{
	struct ckpt_ctx ctx;
	int status, ret;

	init_ctx(&ctx);

	ctx.args = args;
	ctx.whoami = CTX_RESTART;  /* for sanity checked */

	ret = process_args(args);
	if (ret < 0)
		return ret;

	/* freezer preparation */
	if (args->freezer && freezer_prepare(&ctx) < 0)
		goto cleanup;

	/* self-restart ends here: */
	if (args->self) {
		/*
		 * NOTE: while we do attempt to cleanup if an error
		 * occurs, some the following is irreversible - because
		 * of the nature of self-restart...
		 */

		/* private mounts namespace ? */
		if (args->mntns && unshare(CLONE_NEWNS | CLONE_FS) < 0) {
			ckpt_perror("unshare");
			goto cleanup;
		}

		/* chroot ? */
		if (args->root && chroot(args->root) < 0) {
			ckpt_perror("chroot");
			goto cleanup;
		}
		/* remount /dev/pts ? */
		if (args->mnt_pty && ckpt_remount_devpts(&ctx) < 0)
			goto cleanup;

		restart(getpid(), ctx.args->infd,
			RESTART_TASKSELF, args->klogfd);

		/* reach here if restart(2) failed ! */
		ckpt_perror("restart");
		goto cleanup;
	}

	ret = ckpt_read_header(&ctx);
	if (ret < 0) {
		ckpt_perror("read c/r header");
		goto cleanup;
	}
		
	ret = ckpt_read_header_arch(&ctx);
	if (ret < 0) {
		ckpt_perror("read c/r header arch");
		goto cleanup;
	}

	ret = ckpt_read_container(&ctx);
	if (ret < 0) {
		ckpt_perror("read c/r container section");
		goto cleanup;
	}

	ret = ckpt_read_pids(&ctx);
	if (ret < 0) {
		ckpt_perror("read c/r pids");
		goto cleanup;
	}

	ret = ckpt_read_tree(&ctx);
	if (ret < 0) {
		ckpt_perror("read c/r tree");
		goto cleanup;
	}

	/* build creator-child-relationship tree */
	if (hash_init(&ctx) < 0)
		goto cleanup;

	ret = ckpt_build_pids(&ctx);
	if (ret < 0)
		goto cleanup;

	ret = ckpt_build_tree(&ctx);
	if (ret < 0)
		goto cleanup;

	ret = ckpt_fork_feeder(&ctx);
	if (ret < 0)
		goto cleanup;

	/*
	 * Have the first child in the restarted process tree
	 * setup devpts, root-dir and /proc if necessary, ...
	 */
	if (ctx.args->mnt_pty)
		ctx.tasks[0].flags |= TASK_NEWPTS;
	if (ctx.args->mntns)
		ctx.tasks[0].flags |= TASK_NEWNS;
	if (ctx.args->root)
		ctx.tasks[0].flags |= TASK_NEWROOT;

	if (ctx.args->pidns && pid_at_index(&ctx, ctx.tasks[0].pid_ind) != 1) {
		ckpt_dbg("new pidns without init\n");
		if (global_send_sigint == -1)
			global_send_sigint = SIGINT;
		/*
		 * ...unless we have an explicit coordinator, in which case
		 * the coordinator should set up the filesystems and
		 * not the first process in the application process tree.
		 */
		ctx.tasks[0].flags &=
			~(TASK_NEWPTS | TASK_NEWROOT | TASK_NEWNS);
		ret = ckpt_coordinator_pidns(&ctx);
	} else if (ctx.args->pidns) {
		ckpt_dbg("new pidns with init\n");
		ctx.tasks[0].flags |= TASK_NEWPID | TASK_NEWNS;
		if (global_send_sigint == -1)
			global_send_sigint = SIGKILL;
		ret = ckpt_coordinator(&ctx);
	} else {
		ckpt_dbg("subtree (existing pidns)\n");
		if (global_send_sigint == -1)
			global_send_sigint = SIGINT;
		ret = ckpt_coordinator(&ctx);
	}

	if (ret < 0)
		goto cleanup;

	/* success: return pid of root of the restart process tree */
	ret = global_child_pid;

	/* time to release feeder so he can peacefully retire now */
	status = 0;
	if (write(ctx.pipe_out, &status, sizeof(status)) != sizeof(status))
		ret = -1;

 cleanup:
	hash_exit(&ctx);
	exit_ctx(&ctx);

	/* feeder doesn't exit - to avoid SIGCHILD to coordinator */
	if (ret < 0 && global_feeder_pid)
		kill(global_feeder_pid, SIGKILL);
	/* wait for feeder child to terminate (ok of already gone) */
	if (global_feeder_pid)
		waitpid(global_feeder_pid, NULL, 0);

	verbose_status(&ctx);

	if (ctx.success && ctx.error)
		ckpt_verbose("Post restart error: %d\n", ctx.error);
	else if (!ctx.success)
		ret = -1;

	return ret;
}

static int ckpt_parse_status(int status, int mimic, int verbose)
{
	int sig = 0;
	int ret = 0;

	if (verbose && global_sent_sigint)
		ckpt_verbose("Terminated\n");
	if (WIFSIGNALED(status)) {
		sig = WTERMSIG(status);
		if (verbose && !global_sent_sigint)
			ckpt_verbose("Killed %d\n", sig);
		ckpt_dbg("task terminated with signal %d\n", sig);
	} else if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (verbose)
			ckpt_verbose("Exited %d\n", ret);
		ckpt_dbg("task exited with status %d\n", ret);
	}

	if (mimic) {
		if (sig) {
			ckpt_dbg("mimic sig %d\n", sig);
			signal(sig, SIG_DFL);  /* so kill() affects us */
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
		ckpt_perror("WEIRD: collect child task");
		return ctx_set_errno(ctx);
	}

	return ckpt_parse_status(status, mimic, verbose);
}

static int ckpt_remount_devpts(struct ckpt_ctx *ctx)
{
	struct stat ptystat;

	/* make sure /dev/ptmx is a link else we'll just break */
	if (lstat("/dev/ptmx", &ptystat) < 0) {
		ckpt_perror("stat /dev/ptmx");
		return ctx_set_errno(ctx);
	}
	if ((ptystat.st_mode & S_IFMT) != S_IFLNK) {
		ckpt_err("[err] /dev/ptmx must be a link to /dev/pts/ptmx\n");
		return ctx_ret_errno(ctx, ENODEV);
	}

	/* this is unlikely, but maybe we don't want to fail */
	if (umount2("/dev/pts", MNT_DETACH) < 0) {
		if (ckpt_cond_fail(ctx, CKPT_COND_MNTPTY)) {
			ckpt_perror("umount -l /dev/pts");
			return ctx_set_errno(ctx);
		}
		if (ckpt_cond_warn(ctx, CKPT_COND_MNTPTY))
			ckpt_err("[warn] failed to un-mount old /dev/pts\n");
	}
	if (mount("pts", "/dev/pts", "devpts", 0,
		  "ptmxmode=666,newinstance") < 0) {
		ckpt_perror("mount -t devpts -o newinstance");
		return ctx_set_errno(ctx);
	}

	return 0;
}

static int ckpt_close_files(void)
{
	char fdpath[64], *endp;
        struct dirent *dent;
        DIR *dirp;
	int fd;

	/*
	 * Close all the open files reported in /proc/self/task/TID/fd.
	 * If that file is unavailable, do it the traditional way...
	 */
        snprintf(fdpath, PATH_MAX, "/proc/self/task/%d/fd", _gettid());
	dirp = opendir(fdpath);
	if (dirp) {
		while ((dent = readdir(dirp))) {
			fd = strtol(dent->d_name, &endp, 10);
			if (dent->d_name != endp && *endp == '\0')
				close(fd);
		}
		closedir(dirp);
	} else {
		struct rlimit rlim;
		getrlimit(RLIMIT_NOFILE, &rlim);
		for (fd = 0; fd < rlim.rlim_max; fd++)
			close(fd);
	}

	return 0;
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

static int ckpt_probe_child(struct ckpt_ctx *ctx, pid_t pid, char *str)
{
	int status, ret;

	/*
	 * TODO: below we use strerror(); see discussion at:
	 * https://lists.linux-foundation.org/pipermail/containers/2010-August/025165.html
	 */

	/* use waitpid() to probe that a child is still alive */
	ret = waitpid(pid, &status, WNOHANG);
	if (ret == pid) {
		report_exit_status(status, str, 0);
		return ctx_ret_errno(ctx, ECHILD);
	} else if (ret < 0 && errno == ECHILD) {
		ckpt_err("WEIRD: %s exited without trace (%s)\n",
			 str, strerror(errno));
		return ctx_set_errno(ctx);
	} else if (ret != 0) {
		ckpt_err("waitpid for %s (%s)", str, strerror(errno));
		if (ret > 0)
			errno = ECHILD;
		return ctx_set_errno(ctx);
	}
	return 0;
}

/*
 * Remount the /proc with a new instance: tasks that start a new
 * pid-ns need a fresh mount of /proc to reflect their pid-ns.
 */
static int ckpt_remount_proc(struct ckpt_ctx *ctx)
{
	/* this is unlikely, but we don't want to fail */
	if (umount2("/proc", MNT_DETACH) < 0) {
		if (ckpt_cond_fail(ctx, CKPT_COND_MNTPROC)) {
			ckpt_perror("umount -l /proc");
			return ctx_set_errno(ctx);
		}
		if (ckpt_cond_warn(ctx, CKPT_COND_MNTPROC))
			ckpt_err("[warn] failed to un-mount old /proc\n");
	}
	if (mount("proc", "/proc", "proc", 0, NULL) < 0) {
		ckpt_perror("mount -t proc");
		return ctx_set_errno(ctx);
	}

	return 0;
}

#ifdef CLONE_NEWPID
static int __ckpt_coordinator(void *arg)
{
	struct ckpt_ctx *ctx = (struct ckpt_ctx *) arg;

	/* none of this requires cleanup: we're forked ... */

	/* we want to be vocal about sigsegv */
	signal(SIGSEGV, sigsegv_handler);

	/* chroot ? */
	if (ctx->args->root && chroot(ctx->args->root) < 0) {
		ckpt_perror("chroot");
		exit(1);
	}
	/* tasks with new pid-ns need new /proc mount */
	if (ckpt_remount_proc(ctx) < 0)
		exit(1);
	/* remount /dev/pts ? */
	if (ctx->args->mnt_pty && ckpt_remount_devpts(ctx) < 0)
		exit(1);

	if (!ctx->args->wait)
		close(ctx->pipe_coord[0]);

	/* set the exit status properly */
	return ckpt_coordinator(ctx) >= 0 ? 0 : 1;
}

static int ckpt_coordinator_status(struct ckpt_ctx *ctx)
{
	int status;
	int ret;

	close(ctx->pipe_coord[1]);
	ctx->pipe_coord[1] = -1;  /* mark unused */

	ret = read(ctx->pipe_coord[0], &status, sizeof(status));

	close(ctx->pipe_coord[0]);
	ctx->pipe_coord[0] = -1;  /* mark unused */

	if (ret < 0) {
		ckpt_perror("read coordinator status");
		return ctx_set_errno(ctx);
	} else if (ret != sizeof(status)) {
		/* coordinator failed to report */
		ckpt_dbg("Coordinator failed to report status\n");
		return ctx_ret_errno(ctx, EIO);
	} else if (status != 0) {
		/* coordinator reported failure */
		ckpt_dbg("Coordinator reported error\n");
		return ctx_ret_errno(ctx, status);
	}

	/* success ! */
	ctx->success = 1;
	return 0;
}

static int ckpt_coordinator_pidns(struct ckpt_ctx *ctx)
{
	unsigned long flags;
	pid_t coord_pid;
	int copy, ret;
	genstack stk;
	void *sp;

	ckpt_dbg("forking coordinator in new pidns\n");

	/*
	 * The coordinator report restart susccess/failure via pipe.
	 * (It cannot use return value, because in the default case
	 * of --wait --copy-status it is already used to report the
	 * root-task's return value).
	 */
	if (pipe(ctx->pipe_coord) < 0) {
		ckpt_perror("pipe");
		return ctx_set_errno(ctx);
	}

	stk = genstack_alloc(PTHREAD_STACK_MIN);
	if (!stk) {
		ckpt_perror("coordinator genstack_alloc");
		return ctx_set_errno(ctx);
	}
	sp = genstack_sp(stk);

	copy = ctx->args->copy_status;
	ctx->args->copy_status = 1;

	/* in new pidns, we need these: */
	flags = SIGCHLD | CLONE_NEWPID | CLONE_NEWNS;

	coord_pid = clone(__ckpt_coordinator, sp, flags, ctx);
	genstack_release(stk);
	if (coord_pid < 0) {
		ckpt_perror("clone coordinator");
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
	if (ckpt_probe_child(ctx, coord_pid, "coordinator") < 0)
		return -1;

	ctx->args->copy_status = copy;

	ret = ckpt_coordinator_status(ctx);

	if (ret == 0 && ctx->args->wait)
		ret = ckpt_collect_child(ctx);

	return ret;
}
#else /* CLONE_NEWPID */
static int ckpt_coordinator_pidns(struct ckpt_ctx *ctx)
{
	ckpt_err("logical error: ckpt_coordinator_pidns unexpected\n");
	exit(1);
}
#endif /* CLONE_NEWPID */

static int ckpt_coordinator(struct ckpt_ctx *ctx)
{
	unsigned long flags = 0;
	pid_t root_pid;
	int ret;

	root_pid = ckpt_fork_child(ctx, &ctx->tasks[0]);
	if (root_pid < 0)
		return -1;
	global_child_pid = root_pid;

	/* catch SIGCHLD to detect errors during hierarchy creation */
	signal(SIGCHLD, sigchld_handler);
	/* catch SIGINT to propagate ctrl-c to the restarted tasks */
	signal(SIGINT, sigint_handler);

	/*
	 * The child (root_task) may have already exited before the
	 * signal handler was plugged; verify that it's still there.
	 */
	if (ckpt_probe_child(ctx, root_pid, "root task") < 0)
		return -1;

	if (ctx->args->keep_frozen)
		flags |= RESTART_FROZEN;
	if (ctx->args->keep_lsm)
		flags |= RESTART_KEEP_LSM;

	ret = restart(root_pid, ctx->args->infd,
		      flags, ctx->args->klogfd);

	if (ret >= 0) {
		ctx->success = 1;  /* restart succeeded ! */
		ret = 0;
	}

	if (ctx->args->pidns && ctx->tasks[0].pid_ind != 1) {
		/* Report success/failure to the parent */
		if (ret < 0)
			ret = ctx->error;
		if (write(ctx->pipe_coord[1], &ret, sizeof(ret)) < 0) {
			ckpt_perror("failed to report status");
			return ctx_set_errno(ctx);
		}

		/*
		 * Close all open files to eliminate dependencies on
		 * the outside of the container. Else, a subsequent
		 * container-checkpoint will fail due to leaks. (Skip
		 * when debugging to keep output for us visible).
		 */
		if (!global_debug) {
			ckpt_close_files();
			global_verbose = 0;
		}

		/*
		 * If root task isn't container init, we must stay
		 * around and be reaper until all tasks are gone.
		 * Otherwise, container will die as soon as we exit.
		 */
		ret = ckpt_pretend_reaper(ctx);
	} else if (ret == 0 && ctx->args->wait) {
		ret = ckpt_collect_child(ctx);
	}

	return ret;
}

/*
 * ckpt_build_pids - prepare pids array: this array will index into
 * the pids_arr array pointing at the beginning of the individual
 * 'struct ckpt_pids' elements there (as they are of variable size)
 */
static int ckpt_build_pids(struct ckpt_ctx *ctx)
{
	struct ckpt_pids *pids;
	int i = 0, n = 0;
	int depth = 0;
	int s, len;

	/*
	 * Allow for additional pids to be added on demand for
	 * placeholder tasks (each session leader may have at most
	 * one) Added +1 because index count starts from 1.
	 */
	ctx->pids_max = ctx->pids_nr * 2;
	ctx->pids_index = malloc(sizeof(int) * (ctx->pids_max + 1));
	if (!ctx->pids_index) {
		ckpt_perror("malloc pids index");
		return ctx_set_errno(ctx);
	}

	len = ctx->pids_nr * sizeof(*pids) + ctx->vpids_nr * sizeof(__s32);
	if (len <= 0)   /* overflow ? */
		return ctx_ret_errno(ctx, EOVERFLOW);

	while (n < ctx->pids_nr && len > 0) {
		s = sizeof(*pids);

		pids = pids_at_offset(ctx, i);
		if (pids->depth < 0)
			return ctx_ret_errno(ctx, EINVAL);
		s += pids->depth * sizeof(__s32);
		if (s > len)
			return ctx_ret_errno(ctx, EINVAL);

		depth += pids->depth;
		if (depth > ctx->vpids_nr)
			return ctx_ret_errno(ctx, EINVAL);

		ctx->pids_index[n + 1] = i;

		len -= s;
		i += s;
		n++;
	}

	if (n != ctx->pids_nr || depth != ctx->vpids_nr || len != 0)
		return ctx_ret_errno(ctx, EINVAL);

	ctx->pids_cnt = ctx->pids_nr;

	if (!ctx->args->pidns && depth > 0) {
		ckpt_err("need --pidns for nested pidns container");
		return ctx_ret_errno(ctx, EINVAL);
	}

#ifdef CHECKPOINT_DEBUG
	ckpt_dbg("====== PIDS\n");
	for (n = 1; n <= ctx->pids_nr; n++) {
		pids = pids_of_index(ctx, n);
		ckpt_dbg("\t[%d] depth %d pids", n, pids->depth);
		for (i = 0; i <= pids->depth; i++)
			ckpt_dbg_cont(" %d", pids->numbers[i]);
		ckpt_dbg_cont("\n");
	}
	ckpt_dbg("...........\n");
#endif

	return 0;
}

/*
 * ckpt_build_tree - build the task tree data structure which provides
 * the "instructions" to re-create the task tree
 */
static int ckpt_build_tree(struct ckpt_ctx *ctx)
{
	struct task *task;
	int i, found;

	/*
	 * Allow for additional tasks to be added on demand for
	 * placeholder tasks (tgid/sid/pgid ids may each add one)
	 */
	ctx->tasks_max = ctx->pids_nr * 4;
	ctx->tasks = malloc(sizeof(*ctx->tasks) * ctx->tasks_max);
	if (!ctx->tasks) {
		ckpt_perror("malloc tasks array");
		return ctx_set_errno(ctx);
	}

	/*
	 * In subtree checkpoint, the pids objects are the first to
	 * enter the objhash, and get their tags counting from 1.  In
	 * container checkpoint, other objects are inserted first, but
	 * we still assume they count from 1 - so we afjust all the
	 * pids indices by -offset.
	 */
	if (ctx->pid_offset) {
		for (i = 0; i < ctx->tasks_nr; i++) {
			ctx->tasks_arr[i].vpid -= ctx->pid_offset;
			ctx->tasks_arr[i].vtgid -= ctx->pid_offset;
			if (ctx->tasks_arr[i].vpgid > 0)
				ctx->tasks_arr[i].vpgid -= ctx->pid_offset;
			if (ctx->tasks_arr[i].vsid > 0)
				ctx->tasks_arr[i].vsid -= ctx->pid_offset;
		}
	}

	/* initialize tree */
	if (ckpt_init_tree(ctx) < 0)
		return -1;

	/* assign a creator to each task */
	for (i = 0; i < ctx->tasks_cnt; i++) {
		task = &ctx->tasks[i];
		if (task->creator)
			continue;
		if (ckpt_set_creator(ctx, task) < 0)
			return -1;
	}

#ifdef CHECKPOINT_DEBUG
	ckpt_dbg("====== TASKS\n");
	for (i = 0; i < ctx->tasks_cnt; i++) {
		task = &ctx->tasks[i];
		ckpt_dbg("\t[%3d] pid %5d(%3d) (tgid %3d) ppid %5d(%3d)"
			 "  (pgid %3d) sid %5d(%3d) creator %5d(%3d)",
			 i, pid_at_index(ctx, task->pid_ind), task->pid_ind,
			 i < ctx->tasks_nr ? ctx->tasks_arr[i].vtgid : -1,
			 pid_at_index(ctx, task->ppid_ind), task->ppid_ind,
			 i < ctx->tasks_nr ? ctx->tasks_arr[i].vpgid : -1,
			 task->sid_ind >= 0 ?
			 pid_at_index(ctx, task->sid_ind) : -1, task->sid_ind,
			 pid_at_index(ctx, task->creator->pid_ind));
		if (task->next_sib)
			ckpt_dbg_cont(" next %3d",
				      pid_at_index(ctx, task->next_sib->pid_ind));
		if (task->prev_sib)
			ckpt_dbg_cont(" prev %3d",
				      pid_at_index(ctx, task->prev_sib->pid_ind));
		if (task->phantom)
			ckpt_dbg_cont(" placeholder %3d",
				      pid_at_index(ctx, task->phantom->pid_ind));
		ckpt_dbg_cont(" %c%c%c%c%c%c",
		       (task->flags & TASK_THREAD) ? 'T' : ' ',
		       (task->flags & TASK_SIBLING) ? 'P' : ' ',
		       (task->flags & TASK_SESSION) ? 'S' : ' ',
		       (task->flags & TASK_NEWPID) ? 'N' : ' ',
		       (task->flags & TASK_GHOST) ? 'G' : ' ',
		       (task->flags & TASK_DEAD) ? 'D' : ' ');
		ckpt_dbg_cont("\n");
	}
	ckpt_dbg("............\n");
#endif

	/*
	 * For --no-pidns verify that the resulting tree won't create
	 * orphan tasks (comment in ckpt_fork_stub() explain why).
	 */
	if (!ctx->args->pidns) {
		found = 0;
		for (i = 0; i < ctx->tasks_nr; i++) {
			task = &ctx->tasks[i];
			if (!(task->flags & (TASK_GHOST | TASK_DEAD)))
				continue;
			if (!task->children)
				continue;
			ckpt_err("Bad orphan task (#%d) with --no-pidns\n", i);
			found = 1;
		}
		if (found)
			return ctx_ret_errno(ctx, EINVAL);
	}

	/*
	 * Restore the original pid indices if they were adjusted above
	 * because the feeder will feed this array to the kernel.
	 */
	if (ctx->pid_offset) {
		for (i = 0; i < ctx->tasks_nr; i++) {
		ctx->tasks_arr[i].vpid += ctx->pid_offset;
			ctx->tasks_arr[i].vtgid += ctx->pid_offset;
			if (ctx->tasks_arr[i].vpgid > 0)
				ctx->tasks_arr[i].vpgid += ctx->pid_offset;
			if (ctx->tasks_arr[i].vsid > 0)
				ctx->tasks_arr[i].vsid += ctx->pid_offset;
		}
	}

	return 0;
}		

static int ckpt_ghost_task(struct ckpt_ctx *ctx, struct ckpt_pids *pids,
			   int pid_ind, int sid_ind, int ppid_ind)
{
	struct task *task;
	int j;

	task = &ctx->tasks[ctx->tasks_cnt++];

	task->flags = TASK_GHOST;

	task->pid_ind = pid_ind;
	task->ppid_ind = ppid_ind;
	task->tgid_ind = pid_ind;
	task->sid_ind = sid_ind;

	task->children = NULL;
	task->next_sib = NULL;
	task->prev_sib = NULL;
	task->creator = NULL;
	task->phantom = NULL;

	task->ctx = ctx;

	for (j = 0; j <= pids->depth; j++) {
		if (hash_insert(ctx, pids->numbers[j], task, j) < 0)
			return -1;
		/* remember the max pid seen */
		if (pids->numbers[j] > ctx->hash_last_pid[j])
			ctx->hash_last_pid[j] = pids->numbers[j];
	}

	return 0;
}

static struct ckpt_pids *ckpt_consider_pid(struct ckpt_ctx *ctx, int pid_ind)
{
	struct ckpt_pids *pids;

	/* ignore if outside namespace */
	if (pid_ind == 0 || pid_ind == CKPT_PID_ROOT)
		return NULL;

	pids = pids_of_index(ctx, pid_ind);

	/* skip if already handled */
	if (hash_lookup(ctx, pids->numbers[0]))
		return NULL;

	return pids;
}

static int ckpt_set_session(struct ckpt_ctx *ctx, int pid_ind, int ppid_ind)
{
	struct ckpt_pids *pids;

	pids = ckpt_consider_pid(ctx, pid_ind);
	if (!pids)
		return 0;

	return ckpt_ghost_task(ctx, pids, pid_ind, pid_ind, ppid_ind);
}

static int ckpt_set_task(struct ckpt_ctx *ctx, int pid_ind, int ppid_ind)
{
	struct ckpt_pids *pids;
	struct task *parent;

	pids = ckpt_consider_pid(ctx, pid_ind);
	if (!pids)
		return 0;

	parent = hash_lookup_ind(ctx, ppid_ind);
	return ckpt_ghost_task(ctx, pids, pid_ind, parent->sid_ind, ppid_ind);
}

static int _ckpt_valid_pid(struct ckpt_ctx *ctx, pid_t pid, char *which, int i)
{
	if (pid < 0) {
		ckpt_err("Invalid %s %d (for task#%d)\n", which, pid, i);
		errno = EINVAL;
		return 0;
	}
	if (!ctx->args->pidns && pid == 0) {
		if (ckpt_cond_fail(ctx, CKPT_COND_PIDZERO)) {
			ckpt_err("[err] task # %d with %s zero"
				 " (requires --pidns)\n", i + 1, which);
			errno = EINVAL;
			return 0;
		} else if (ckpt_cond_warn(ctx, CKPT_COND_PIDZERO)) {
			ckpt_err("[warn] task # %d with %s zero"
				 " (consider --pidns)\n", i + 1, which);
		}
	}
	return 1;
}

static int ckpt_valid_pid(struct ckpt_ctx *ctx, int index, char *which, int i)
{
	struct ckpt_pids *pids;
	int j;

	pids = pids_of_index(ctx, index);
	if (pids == NULL)
		return 0;
	for (j = 0; j <= pids->depth; j++) {
		if (!_ckpt_valid_pid(ctx, pids->numbers[j], which, i))
			return 0;
	}
	return 1;
}

static int ckpt_alloc_pid(struct ckpt_ctx *ctx, int depth)
{
	struct ckpt_pids *pids;
	int j, n, last, len;
	int pid_ind;

	len = sizeof(*pids) + depth * sizeof(__s32);

	/* need to expand the ctx->pids_new[] array ? */
	if (ctx->pids_off + len > ctx->pids_len) {
		pids = realloc(ctx->pids_new, ctx->pids_len * 3 / 2);
		if (!pids) {
			ckpt_perror("allocate new pids table");
			return ctx_set_errno(ctx);
		}
		ctx->pids_new = pids;
	}

	/* need to expand the ctx->pids_index[] array ? */
	if (ctx->pids_cnt >= ctx->pids_max)  {
		/* shouldn't happen, beacuse we prepared enough */
		ckpt_err("out of space in task table !");
		return ctx_ret_errno(ctx, EOVERFLOW);
	}

	ctx->pids_cnt += 1;
	pid_ind = ctx->pids_cnt;

	ctx->pids_index[pid_ind] = ctx->pids_off;
	ctx->pids_off += len;

	/*
	 * allocate an unused pid for the placeholder in each pid-namespace
	 * (this will become inefficient if pid-space is exhausted)
	 */

	pids = pids_of_index(ctx, pid_ind);

	for (j = 0; j <= depth; j++) {
		n = 0;
		last = ctx->hash_last_pid[j];

		do {
			if (last >= ctx->pid_max)
				last = CKPT_RESERVED_PIDS;
			else
				last++;

			if (n++ == ctx->pid_max) {  /* ohhh... */
				ckpt_err("pid namsepace exhausted");
				return ctx_ret_errno(ctx, EOVERFLOW);
			}
		} while (hash_lookup_level(ctx, last, j));

		ctx->hash_last_pid[j] = last;
		pids->numbers[j] = last;
	}

	return pid_ind;
}

static int ckpt_init_tree(struct ckpt_ctx *ctx)
{
	struct ckpt_task_pids *tasks_arr;
	struct ckpt_pids *pids;
	struct task *task;
	int root_pid_ind;
	int root_sid_ind;
	int ppid_ind;
	int i, j;

	tasks_arr = ctx->tasks_arr;

	root_pid_ind = tasks_arr[0].vpid;
	root_sid_ind = tasks_arr[0].vsid;

	/*
	 * Any zero value (tgid/pgid/sid) means that at checkpoint the
	 * original pid came from an ancestor pid-ns. If we find any,
	 * the caller must also have requested --pidns, otherwise fail.
	 * This is done in _ckpt_valid_pid(), but users can choose to
	 * only issue a warning, and we'll convert them to inherit the
	 * sid of the root task instead.
	 *
	 * The case where root_sid != root_pid is special. It must be
	 * from a subtree checkpoint (in container, root_sid is either
	 * same as root_pid or 0), and root_sid was inherited from an
	 * ancestor of that subtree.
	 *
	 * When creating the tasks tree, the root task will inherit
	 * its sid from its ancestor (usually from the coordinator;
	 * however, for --pidns and non-init root task it will be the
	 * stub init task inserted by us). This sid will be whatever
	 * 'restart' process (or our caller) current has.
	 *
	 * For that, we force the root-task's sid and all references
	 * to it to be CKPT_PID_ROOT. This tells restart to treat them
	 * as such, and ensures that we don't call setsid() on the
	 * root task (because sid != pid). CKPT_PID_ROOT is gracefully
	 * handled both by ckpt_set_creator() when tracking the sid
	 * heritage, and by the kernel when restoring a task's pgid.
	 *
	 * (Note that this still works even if the coordinator's sid
	 * is "used" by a restarting task: a new-pidns restart will
	 * fail because the pid is in use, and in an old-pidns restart
	 * the task will be assigned a new pid anyway).
	 */

	/* forcing root_sid to -1, will make comparisons below fail */
	if (root_sid_ind == root_pid_ind)
		root_sid_ind = -1;

	/* populate with known tasks */
	for (i = 0; i < ctx->tasks_nr; i++) {
		task = &ctx->tasks[i];

		task->flags = 0;

		/* pid and tgid must be native in our namespace ! */
		if (tasks_arr[i].vpid == 0 || tasks_arr[i].vtgid == 0)
			return ctx_ret_errno(ctx, EINVAL);

		if (!ckpt_valid_pid(ctx, tasks_arr[i].vpid, "pid", i))
			return ctx_ret_errno(ctx, EINVAL);
		else if (!ckpt_valid_pid(ctx, tasks_arr[i].vtgid, "tgid", i))
			return ctx_ret_errno(ctx, EINVAL);
		else if (!ckpt_valid_pid(ctx, tasks_arr[i].vsid, "sid", i))
			return ctx_ret_errno(ctx, EINVAL);
		else if (!ckpt_valid_pid(ctx, tasks_arr[i].vpgid, "pgid", i))
			return ctx_ret_errno(ctx, EINVAL);

		if (tasks_arr[i].vsid == root_sid_ind)
			tasks_arr[i].vsid = CKPT_PID_ROOT;
		if (tasks_arr[i].vpgid == root_sid_ind)
			tasks_arr[i].vpgid = CKPT_PID_ROOT;

		task->pid_ind = tasks_arr[i].vpid;
		task->ppid_ind = tasks_arr[i].vppid;
		task->tgid_ind = tasks_arr[i].vtgid;
		task->sid_ind = tasks_arr[i].vsid;

		task->children = NULL;
		task->next_sib = NULL;
		task->prev_sib = NULL;
		task->creator = NULL;
		task->phantom = NULL;

		task->ctx = ctx;

		pids = pids_of_index(ctx, tasks_arr[i].vpid);
		for (j = 0; j <= pids->depth; j++) {
			if (hash_insert(ctx, pids->numbers[j], task, j) < 0)
				return -1;
			/* remember the max pid seen */
			if (pids->numbers[j] > ctx->hash_last_pid[j])
				ctx->hash_last_pid[j] = pids->numbers[j];
		}
	}

	ctx->tasks_cnt = ctx->tasks_nr;

	/*
	 * Add sids unaccounted for (no tasks): find those orphan pids
	 * that are used as some task's sid, and create ghost session
	 * leaders for them. Since they should be session leaders, we
	 * must do this before adding other ghost tasks for tgid/pgid
	 * below: the latter is added a non-session leader.
	 */
	for (i = 0; i < ctx->tasks_nr; i++) {
		/*
		 * An unaccounted-for sid belongs to a task that was a
		 * session leader and died. We can safely set its parent
		 * (and creator) to be the root task.
		 */

		if (ckpt_set_session(ctx, tasks_arr[i].vsid, root_pid_ind) < 0)
			return -1;
	}

	/*
	 * Add tgids/pgids unaccounted for (no tasks): find those
	 * orphan tgids/pgids and create ghost tasks for them.
	 */
	for (i = 0; i < ctx->tasks_nr; i++) {
		/*
		 * An sid == 0 means that the session was inherited an
		 * ancestor of root_task, and more specifically, via
		 * root_task itself: make root_task our parent.
		 */

		ppid_ind = tasks_arr[i].vsid;
		if (ppid_ind == 0 || ppid_ind == CKPT_PID_ROOT)
			ppid_ind = root_pid_ind;

		/*
		 * If a pid belongs to a dead thread group leader, we
		 * need to add it with the same sid as current (and
		 * other) threads.
		 */
		if (ckpt_set_task(ctx, tasks_arr[i].vtgid, ppid_ind) < 0)
			return -1;

		/*
		 * If pgrp == sid, then the pgrp/sid will already have
		 * been hashed by now (e.g. by the call above) and the
		 * ckpt_set_task() will return promptly.
		 * If pgrp != sid, then the pgrp 'owner' must have the
		 * same sid as us: all tasks with same pgrp must have
		 * their sid matching.
		 */
		if (ckpt_set_task(ctx, tasks_arr[i].vpgid, ppid_ind) < 0)
			return -1;
	}

	/* mark root task(s), and set its "creator" to be zero_task */
	ckpt_init_task(ctx)->flags |= TASK_ROOT;
	ckpt_init_task(ctx)->creator = &zero_task;

	ckpt_dbg("total tasks (excluding ghosts): %d\n", ctx->tasks_nr);
	ckpt_dbg("total tasks (including ghosts): %d\n", ctx->tasks_cnt);
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
 * are TASK_ROOT, TASK_GHOST, TASK_THREAD, TASK_SIBLING (that asks to
 * inherit the parent via CLONE_PARENT), TASK_SESSION (that asks to
 * inherit a session id), TASK_NEWPID (that asks to start a new pid
 * namespace), and TASK_DEAD. The algorithm loops through all the
 * entries in the table:
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
	struct task *session;
	struct task *parent;
	struct task *creator;

	session = hash_lookup_ind(ctx, task->sid_ind);
	parent = hash_lookup_ind(ctx, task->ppid_ind);

	if (task == ckpt_init_task(ctx)) {
		ckpt_err("pid %d: logical error\n",
			 pid_at_index(ctx, ckpt_init_task(ctx)->pid_ind));
		return ctx_ret_errno(ctx, EINVAL);
	}

	/* sid == 0 must have been inherited from outside the container */
	if (task->sid_ind == 0 || task->sid_ind == CKPT_PID_ROOT)
		task->flags |= TASK_SESSION;

	if (task->tgid_ind != task->pid_ind) {
		/* thread: creator is thread-group-leader */
		ckpt_dbg("pid %d: thread tgid %d\n",
			 pid_at_index(ctx, task->pid_ind),
			 pid_at_index(ctx, task->tgid_ind));
		creator = hash_lookup_ind(ctx, task->tgid_ind);
		if (!creator) {
			/* oops... thread group leader MIA */
			ckpt_err("pid %d: no leader %d\n",
				 pid_at_index(ctx, task->pid_ind),
				 pid_at_index(ctx, task->tgid_ind));
			return ctx_ret_errno(ctx, EINVAL);
		}
		task->flags |= TASK_THREAD;
	} else if (task->ppid_ind == 0 || !parent) {
		/* only root_task can have ppid == 0, parent must always exist */
		ckpt_err("pid %d: invalid ppid %d\n",
			 pid_at_index(ctx, task->pid_ind),
			 pid_at_index(ctx, task->ppid_ind));
		return ctx_ret_errno(ctx, EINVAL);
	} else if (task->pid_ind == task->sid_ind) {
		/* session leader: creator is parent */
		ckpt_dbg("pid %d: session leader\n",
			 pid_at_index(ctx, task->pid_ind));
		creator = parent;
	} else if (task->flags & TASK_DEAD) {
		/* dead: creator is session leader */
		ckpt_dbg("pid %d: task is dead\n",
			 pid_at_index(ctx, task->pid_ind));
		creator = session;
	} else if (task->sid_ind == parent->sid_ind) {
		/* (non-session-leader) inherit: creator is parent */
		ckpt_dbg("pid %d: inherit sid %d\n",
			 pid_at_index(ctx, task->pid_ind),
			 pid_at_index(ctx, task->sid_ind));
		creator = parent;
	} else if (task->ppid_ind == 1) {
		/* (non-session-leader) orphan: creator is dummy */
		ckpt_dbg("pid %d: orphan session %d\n",
			 pid_at_index(ctx, task->pid_ind),
			 pid_at_index(ctx, task->sid_ind));
		if (!session->phantom)
			if (ckpt_placeholder_task(ctx, task) < 0)
				return -1;
		creator = session->phantom;
	} else {
		/* first make sure we know the session's creator */
		if (!session->creator) {
			/* (non-session-leader) recursive: session's creator */
			ckpt_dbg("pid %d: recursive session creator %d\n",
				 pid_at_index(ctx, task->pid_ind),
				 pid_at_index(ctx, task->sid_ind));
			if (ckpt_set_creator(ctx, session) < 0)
				return -1;
		}
		/* then use it to decide what to do */
		if (session->creator->pid_ind == task->ppid_ind) {
			/* init must not be sibling creator (CLONE_PARENT) */
			if (session == ckpt_init_task(ctx)) {
				ckpt_err("pid %d: sibling session prohibited"
					 " with init as creator\n",
					 pid_at_index(ctx, task->pid_ind));
				return ctx_ret_errno(ctx, EINVAL);
			}
			/* (non-session-leader) sibling: creator is sibling */
			ckpt_dbg("pid %d: sibling session %d\n",
				 pid_at_index(ctx, task->pid_ind),
				 pid_at_index(ctx, task->sid_ind));
			creator = session;
			task->flags |= TASK_SIBLING;
		} else {
			/* (non-session-leader) session: fork before setsid */
			ckpt_dbg("pid %d: propagate session %d\n",
				 pid_at_index(ctx, task->pid_ind),
				 pid_at_index(ctx, task->sid_ind));
			creator = parent;
			task->flags |= TASK_SESSION;
		}
	}

	if (creator->children) {
		struct task *next = creator->children;

		task->next_sib = next;
		next->prev_sib = task;
	}

	ckpt_dbg("pid %d: creator set to %d\n",
		 pid_at_index(ctx, task->pid_ind),
		 pid_at_index(ctx, creator->pid_ind));
	task->creator = creator;
	creator->children = task;

	if (task->flags & TASK_SESSION)
		if (ckpt_propagate_session(ctx, task) < 0)
			return -1;

	return 0;
}

static int ckpt_placeholder_task(struct ckpt_ctx *ctx, struct task *task)
{
	struct task *session;
	struct task *holder;
	int pid_ind;

	session = hash_lookup_ind(ctx, task->sid_ind);
	holder = &ctx->tasks[ctx->tasks_cnt++];

	if (ctx->tasks_cnt > ctx->tasks_max) {
		/* shouldn't happen, beacuse we prepared enough */
		ckpt_err("out of space in task table !");
		return ctx_ret_errno(ctx, EOVERFLOW);
	}

	pid_ind = ckpt_alloc_pid(ctx, pids_of_index(ctx, task->pid_ind)->depth);
	if (pid_ind < 0)
		return -1;

	holder->flags = TASK_DEAD;

	holder->pid_ind = pid_ind;
	holder->ppid_ind = ckpt_init_task(ctx)->pid_ind;
	holder->tgid_ind = pid_ind;
	holder->sid_ind = task->sid_ind;

	holder->children = NULL;
	holder->next_sib = NULL;
	holder->prev_sib = NULL;
	holder->creator = NULL;
	holder->phantom = NULL;

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
	struct task *session;
	struct task *creator;

	session = hash_lookup_ind(ctx, task->sid_ind);

	/*
	 * propagate the TASK_SESSION up the ancestry until we reach
	 * our session owner, so that all of them pass the sid we wnat
	 * down before (possibly) changing their own.
	 */

	do {
		ckpt_dbg("pid %d: set session\n",
			 pid_at_index(ctx, task->pid_ind));
		task->flags |= TASK_SESSION;

		creator = task->creator;
		/*
		 * If we reached the root task, and the root task is
		 * not our real parent, then we add a placeholder here
		 * as a child of the root task and our creator. The
		 * placeholder will inherit the session, and pass it
		 * to us (and then terminate).
		 */
		if (creator == ckpt_init_task(ctx) &&
		    creator != hash_lookup_ind(ctx, task->ppid_ind)) {
			if (ckpt_placeholder_task(ctx, task) < 0)
				return -1;
		}

		ckpt_dbg("pid %d: moving up to %d\n",
			 pid_at_index(ctx, task->pid_ind),
			 pid_at_index(ctx, creator->pid_ind));
		task = creator;

		if(!task->creator) {
			if (ckpt_set_creator(ctx, task) < 0)
				return -1;
		}

		/*
		 * (Note that now @task already points to our creator!)
		 * We don't propagate anymore if:
		 *
		 * (a) our creator has the same session as us
		 * (b) our creator is the root task of the restart
		 * (c) our creator already has TASK_SESSION,
		 * (d) our creator's creator is our session (leader)
		 */

	} while (hash_lookup_ind(ctx, task->sid_ind) != session &&
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
 * created with parent inheritance. Finally, the task will invoke
 * sys_restart() which does not return (if successful).
 *
 * Tasks marked TASK_DEAD or TASK_GHOST are both destined to terminate
 * anyway; both use flag RESTART_GHOST for sys_restart(), which will
 * result in a call to do_exit().
 */
static int ckpt_make_tree(struct ckpt_ctx *ctx, struct task *task)
{
	struct task *child;
	struct pid_swap swap;
	unsigned long flags = 0;
	pid_t newpid;
	int ret;

	ckpt_dbg("pid %d: pid %d sid %d parent %d\n",
		 pid_at_index(ctx, task->pid_ind),
		 _gettid(), getsid(0), getppid());

	/* 1st pass: fork children that inherit our old session-id */
	for (child = task->children; child; child = child->next_sib) {
		if (child->flags & TASK_SESSION) {
			ckpt_dbg("pid %d: fork child %d with session\n",
				 pid_at_index(ctx, task->pid_ind),
				 pid_at_index(ctx, child->pid_ind));
			newpid = ckpt_fork_child(ctx, child);
			if (newpid < 0)
				return ctx_set_errno(ctx);
		}
	}

	/* change session id, if necessary */
	if (task->pid_ind == task->sid_ind) {
		ret = setsid();
		if (ret < 0) {
			ckpt_perror("setsid");
			return ctx_set_errno(ctx);
		}
	}

	/* 2st pass: fork children that inherit our new session-id */
	for (child = task->children; child; child = child->next_sib) {
		if (!(child->flags & TASK_SESSION)) {
			ckpt_dbg("pid %d: fork child %d without session\n",
				 pid_at_index(ctx, task->pid_ind),
				 pid_at_index(ctx, child->pid_ind));
			newpid = ckpt_fork_child(ctx, child);
			if (newpid < 0)
				return ctx_set_errno(ctx);
		}
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
	swap.old = pid_at_index(ctx, task->pid_ind);
	swap.new = _gettid();
	ret = write(ctx->pipe_out, &swap, sizeof(swap));
	if (ret != sizeof(swap)) {
		ckpt_perror("write swap");
		return ctx_ret_errno(ctx, EPIPE);
	}

	/*
	 * At this point restart may have already begun in the kernel.
	 * We shouldn't be doing much until sys_restart() below. With
	 * threads, sys_restart() ensures that all members of a thread
	 * group are ready before restoring any of them.
	 */

	/*
	 * Ghost tasks are not restarted and end up dead, but their
	 * pids are referred to by other tasks' pgids (also sids, that
	 * are already properly set by now). Therefore, they stick
	 * around until those tasks actually restore their pgrp, and
	 * then exit (more precisely, killed). The RESTART_GHOST flag
	 * tells the kernel that they are not to be restored.
	 */
	if (task->flags & (TASK_GHOST | TASK_DEAD))
		flags |= RESTART_GHOST;

	/* on success this doesn't return */
	ckpt_dbg("about to call sys_restart(), flags %#lx\n", flags);
	ret = restart(0, 0, flags, CHECKPOINT_FD_NONE);
	if (ret < 0)
		ckpt_perror("task restore failed");
	return ret;
}

int ckpt_fork_stub(void *data)
{
	struct task *task = (struct task *) data;
	struct ckpt_ctx *ctx = task->ctx;

	/* none of this requires cleanup: we're forked ... */

	/* chroot ? */
	if ((task->flags & TASK_NEWROOT) && chroot(ctx->args->root) < 0)
		return ctx_set_errno(ctx);
	/* tasks with new pid-ns need new /proc mount */
	if ((task->flags & TASK_NEWPID) && ckpt_remount_proc(ctx) < 0)
		return ctx_set_errno(ctx);
	/* remount /dev/pts ? */
	if ((task->flags & TASK_NEWPTS) && ckpt_remount_devpts(ctx) < 0)
		return ctx_set_errno(ctx);

	/*
	 * In restart into a new pid namespace (--pidns), coordinator
	 * is the container init, hence if it terminated permatutely
	 * then the task hierarchy will be cleaned up automagically.
	 *
	 * In restart into existing namespace (--no-pidns) we ensure
	 * proper cleanup of the new hierarchy in case of coordinator
	 * death by asking to be killed then. When restart succeeds,
	 * it will have replaced this with the original value.
	 *
	 * This works because in the --no-pidns case, the hierarchy of
	 * tasks does not contain zombies; else, there must also be a
	 * container init, whose pid (==1) is clearly already taken.
	 * This is verified in ckpt_build_tree().
	 *
	 * Thus, if a the parent of this task dies before this prctl()
	 * call, it suffices to test getppid() == task->parent_pid.
	 *
	 * We use SIGUSR1 so that we can catch it and issue an error
	 * or debug message when this happens.
	 */
	if (!ctx->args->pidns) {
		signal(SIGUSR1, sigusr1_handler);
		if (prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) < 0) {
			ckpt_perror("prctl");
			return ctx_set_errno(ctx);
		}
		if (getppid() != task->real_parent) {
			ckpt_err("[%d]: parent is MIA (%d != %d)\n",
				 _getpid(), getppid(), task->real_parent);
			if (errno == 0)
				errno = ECHILD;
			return ctx_set_errno(ctx);
		}
	}

	/* if user requested freeze at end - add ourself to cgroup */
	if (ctx->args->freezer && freezer_register(ctx, _getpid())) {
		ckpt_err("[%d]: failed add to freezer cgroup\n", _getpid());
		return ctx_set_errno(ctx);
	}

	/* root has some extra work */
	if (task->flags & TASK_ROOT) {
		ctx->root_pid = _getpid();
		ckpt_dbg("root task pid %d\n", _getpid());
	}

	return ckpt_make_tree(ctx, task);
}

static pid_t ckpt_fork_child(struct ckpt_ctx *ctx, struct task *child)
{
	struct clone_args clone_args;
	struct ckpt_pids *pids, *ppids;
	unsigned long flags = SIGCHLD;
	pid_t *numbers;
	pid_t pid = 0;
	genstack stk;
	int j;

	ckpt_dbg("fork child vpid %d flags %#x\n",
		 pid_at_index(ctx, child->pid_ind), child->flags);

	stk = genstack_alloc(PTHREAD_STACK_MIN);
	if (!stk) {
		ckpt_perror("ckpt_fork_child genstack_alloc");
		return ctx_set_errno(ctx);
	}

	if (child->flags & TASK_THREAD)
		flags |= CLONE_THREAD | CLONE_SIGHAND | CLONE_VM;
	else if (child->flags & TASK_SIBLING)
		flags |= CLONE_PARENT;

	memset(&clone_args, 0, sizeof(clone_args));
	clone_args.nr_pids = 1;

	pids = pids_of_index(ctx, child->pid_ind);
	ppids = pids_of_index(ctx, child->creator->pid_ind);
	numbers = pids_zero.numbers;

	/* select pid if --pids, otherwise it's 0 */
	if (ctx->args->pids) {
		clone_args.nr_pids = pids->depth + 1;
		numbers = pids->numbers;
#ifndef CLONE_NEWPID
		if (child->piddepth > child->creator->piddepth) {
			ckpt_err("nested pidns but CLONE_NEWPID undefined");
			ctx_ret_errno(ctx, ENOSYS);
		} else if (child->flags & TASK_NEWPID) {
			ckpt_err("TASK_NEWPID set but CLONE_NEWPID undefined");
			ctx_ret_errno(ctx, ENOSYS);
		}
#else /* CLONE_NEWPID */
		if (pids->depth > ppids->depth + 1) {
			ckpt_err("unsupported form of pidns nesting");
			ctx_ret_errno(ctx, ENOSYS);
		}
		if (pids->depth > ppids->depth) {
			child->flags |= TASK_NEWPID;
			flags |= CLONE_NEWPID;
			clone_args.nr_pids--;
			numbers = pids->numbers + 1;
		} else if (child->flags & TASK_NEWPID) {
			/*
			 * This happens for a restart with --pidns in which
			 * the root task is init in its namespace (the flag
			 * TASK_NEWPID was set for this root task).
			 */
			assert(pids->depth == 0);
			flags |= CLONE_NEWPID;
			clone_args.nr_pids--;
			numbers = pids->numbers + 1;
		}
#endif /* CLONE_NEWPID */
	}

	if (child->flags & TASK_NEWNS)
		flags |= CLONE_NEWNS;

	if (child->flags & (TASK_SIBLING | TASK_THREAD))
		child->real_parent = getppid();
	else
		child->real_parent = _getpid();

	clone_args.child_stack = (unsigned long)genstack_base(stk);
	clone_args.child_stack_size = genstack_size(stk);

	ckpt_dbg("task %d forking with flags %lx numpids %d\n",
		 pid_at_index(ctx, child->pid_ind), flags, clone_args.nr_pids);
	ckpt_dbg("task %d pids:", pid_at_index(ctx, child->pid_ind));
	for (j = 0; j < clone_args.nr_pids; j++)
		ckpt_dbg_cont(" %d\n", numbers[j]);
	ckpt_dbg("...\n");

	pid = eclone(ckpt_fork_stub, child, flags, &clone_args, numbers);
	if (pid < 0) {
		ckpt_perror("eclone");
		ctx_set_errno(ctx);
	}

	if (pid < 0 || !(child->flags & TASK_THREAD))
		genstack_release(stk);

	ckpt_dbg("forked child vpid %d (asked %d)\n",
		 pid, pid_at_index(ctx, child->pid_ind));

	if (ctx->args->pids && pids->numbers[0] != 1 &&
	    pid != pids->numbers[ppids->depth]) {
		ckpt_err("failed to create specific pid with eclone\n");
		return ctx_ret_errno(ctx, EAGAIN);
	}

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
	pid_t pid;
	int ret;

	if (pipe(ctx->pipe_feed)) {
		ckpt_perror("pipe");
		return ctx_set_errno(ctx);
	}

	if (pipe(ctx->pipe_child) < 0) {
		ckpt_perror("pipe");
		return ctx_set_errno(ctx);
	}

	pid = fork();
	if (pid < 0) {
		ckpt_perror("feeder thread");
		return ctx_set_errno(ctx);
	} else if (pid == 0) {
		ret = ckpt_do_feeder(ctx);
		exit(ret);
	}

	global_feeder_pid = pid;

	/* children pipe: used for status reports from children */
	close(ctx->pipe_child[0]);
	ctx->pipe_out = ctx->pipe_child[1];

	ctx->pipe_child[0] = -1;  /* mark unused */
	ctx->pipe_child[1] = -1;  /* mark unused */

	/* feeder pipe: feeder writes, kernel's sys_restart reads */
	close(ctx->pipe_feed[1]);
	ctx->args->infd = ctx->pipe_feed[0];

	ctx->pipe_feed[0] = -1;  /* mark unused */
	ctx->pipe_feed[1] = -1;  /* mark unused */

	return 0;
}

static void ckpt_abort(struct ckpt_ctx *ctx, char *str)
{
	/* should only be called by the feeder */
	assert(ctx->whoami == CTX_FEEDER);

	ckpt_perror(str);
	kill(ctx->root_pid, SIGKILL);
	exit(1);
}

/* read/write image data as is, blindly */
static void ckpt_read_write_blind(struct ckpt_ctx *ctx)
{
	int ret;

	/* called by the feeder, so use stdin/stdout */
	assert(ctx->whoami == CTX_FEEDER);

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
}

/* read/write image data while inspecting it */
static void ckpt_read_write_inspect(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr h;
	int len, ret;

	/* called by the feeder, so use stdin/stdout */
	assert(ctx->whoami == CTX_FEEDER);

	while (1) {
		ret = _ckpt_read(STDIN_FILENO, &h, sizeof(h));
		if (ret == 0)
			break;
		if (ret < 0)
			ckpt_abort(ctx, "read input");
		if (h.len < sizeof(h)) {
			errno = EINVAL;
			ckpt_abort(ctx, "invalid record");
		}

		ret = ckpt_write(STDOUT_FILENO, &h, sizeof(h));
		if (ret < 0)
			ckpt_abort(ctx, "write output");

		h.len -= sizeof(h);
		if (h.type == CKPT_HDR_ERROR) {
			len = (h.len > BUFSIZE ? BUFSIZE : h.len);
			ret = read(STDIN_FILENO, ctx->buf, len);
			if (ret < 0)
				ckpt_abort(ctx, "error record");
			errno = EIO;
			ctx->buf[len - 1] = '\0';
			ckpt_abort(ctx, &ctx->buf[1]);
		}
		ckpt_dbg("c/r read input %d\n", h.len);

		while (h.len) {
			len = (h.len > BUFSIZE ? BUFSIZE : h.len);
			ret = read(STDIN_FILENO, ctx->buf, len);
			if (ret == 0)
				ckpt_abort(ctx, "short record");
			if (ret < 0)
				ckpt_abort(ctx, "read input");

			h.len -= ret;
			ret = ckpt_write(STDOUT_FILENO, ctx->buf, ret);
			if (ret < 0)
				ckpt_abort(ctx, "write output");
		}
	}
}

/*
 * feeder process: delegates checkpoint image stream to the kernel.
 * In '--no-pids' mode, transform the pids array (struct ckpt_pids)
 * on the fly and feed the result to the "init" task of the restart
 */
static int ckpt_do_feeder(struct ckpt_ctx *ctx)
{
	int status;

	ctx->whoami = CTX_FEEDER;  /* for sanity checks */

	if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0)
		ckpt_abort(ctx, "prctl");

	/*
	 * feeder has a separate file descriptor table, so
	 * close/dup/open etc do not affect original caller
	 */

	/* children pipe */
	close(ctx->pipe_child[1]);
	ctx->pipe_in = ctx->pipe_child[0];

	/* feeder pipe */
	close(ctx->pipe_feed[0]);
	if (ctx->pipe_feed[1] != STDOUT_FILENO) {
		dup2(ctx->pipe_feed[1], STDOUT_FILENO);
		close(ctx->pipe_feed[1]);
	}

	/*
	 * we don't need to mark pipe_child[0,1] and pipe_feed[0,1]
	 * because the feeder doesn't affect the original caller
	 */

	if (ckpt_adjust_pids(ctx) < 0)
		ckpt_abort(ctx, "collect pids");

	if (ckpt_write_header(ctx) < 0)
		ckpt_abort(ctx, "write c/r header");

	if (ckpt_write_header_arch(ctx) < 0)
		ckpt_abort(ctx, "write c/r header arch");

	if (ckpt_write_container(ctx) < 0)
		ckpt_abort(ctx, "write container section");

	if (ckpt_write_pids(ctx) < 0)
		ckpt_abort(ctx, "write c/r pids");

	if (ckpt_write_tree(ctx) < 0)
		ckpt_abort(ctx, "write c/r tree");

	/* read rest -> write rest */
	if (ctx->args->inspect)
		ckpt_read_write_inspect(ctx);
	else
		ckpt_read_write_blind(ctx);

	/* wait for parent (coordinator) to confirm, to avoid
	   prematurely interrupting the restart with SIGCHLD */
	if (read(ctx->pipe_in, &status, sizeof(status)) != sizeof(status))
		ckpt_abort(ctx, "read coord status");

	close(ctx->pipe_in);  /* no need to mark unused */
	return status;
}

/*
 * ckpt_adjust_pids: transform the pids array (struct ckpt_pids) by
 * substituing actual pid values for original pid values.
 *
 * Collect pids reported by the newly created tasks; each task sends
 * a 'struct pid_swap' indicating old- and new-pid. Then modify the
 * the pids array accordingly.
 */
static int ckpt_adjust_pids(struct ckpt_ctx *ctx)
{
	struct ckpt_pids *pids, *copy;
	struct pid_swap swap;
	int n, m, off, len, ret;
	pid_t coord_sid;

	coord_sid = getsid(0);

	/*
	 * Make a copy of the original array to fix a nifty bug where
	 * two tasks in original image with pids A, B, restart with
	 * pids swapped (B and A), for instance -
	 *    original pid array:    [][][A][][B][]...
	 *    first, swap B with A:  [][][A][][A][]...
	 *    then, swap A with B:   [][][B][][B][]...
	 *    but correct should be: [][][B][][A][]...
	 */

	len = ctx->pids_nr * sizeof(*pids) + ctx->vpids_nr * sizeof(__s32);

#ifdef CHECKPOINT_DEBUG
	ckpt_dbg("====== PIDS ARRAY\n");
	for (m = 0; m < ctx->pids_nr; m++) {
		pids = pids_of_index(ctx, m + 1);
		ckpt_dbg("[%d] pid %d depth %d\n",
			 m, pids->numbers[0], pids->depth);
	}
	ckpt_dbg("............\n");
#endif

	memcpy(ctx->pids_copy, ctx->pids_arr, len);

	/* read in 'pid_swap' data and adjust ctx->pids */
	for (n = 0; n < ctx->tasks_cnt; n++) {
		/* get pid info from next task */
		ret = read(ctx->pipe_in, &swap, sizeof(swap));
		if (ret < 0)
			ckpt_abort(ctx, "read pipe");

		/* swapping isn't needed with '--pids' */
		if (ctx->args->pids)
			continue;

		ckpt_dbg("c/r swap old %d new %d\n", swap.old, swap.new);
		for (m = 0; m < ctx->pids_nr; m++) {
			off = ctx->pids_index[m + 1];
			pids = pids_at_offset(ctx, off);
			copy = pids_copy_at_offset(ctx, off);
			if (pids->numbers[0] == swap.old)
				copy->numbers[0] = swap.new;
		}
	}

	free(ctx->pids_arr);
	ctx->pids_arr = ctx->pids_copy;
	ctx->pids_copy = NULL;

#ifdef CHECKPOINT_DEBUG
	if (!ctx->args->pids) {
		ckpt_dbg("====== PIDS ARRAY (swaped)\n");
		for (m = 0; m < ctx->pids_nr; m++) {
			pids = pids_of_index(ctx, m + 1);
			ckpt_dbg("[%d] pid %d depth %d\n",
				 m, pids->numbers[0], pids->depth);
		}
		ckpt_dbg("............\n");
	}
#endif

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
	/* called by the feeder, so use stdout */
	assert(ctx->whoami == CTX_FEEDER);

	return ckpt_write(STDOUT_FILENO, h, h->len);
}

int ckpt_write_obj_ptr(struct ckpt_ctx *ctx, void *buf, int n, int type)
{
	struct ckpt_hdr h;
	int ret;

	/* called by the feeder, so use stdout */
	assert(ctx->whoami == CTX_FEEDER);

	h.type = type;
	h.len = n + sizeof(h);
	ret = ckpt_write(STDOUT_FILENO, &h, sizeof(h));
	if (!ret)
		ret = ckpt_write(STDOUT_FILENO, buf, n);
	return ret;
}

/*
 * low-level read
 *   _ckpt_read - read 'count' bytes to 'buf', or EOF
 *   ckpt_read - read 'count' bytes to 'buf' (EOF disallowed)
 *   ckpt_read_obj - read up to 'n' bytes of object into 'buf'
 *   ckpt_read_obj_type - read up to 'n' bytes of object type 'type' into 'buf'
 *   ckpt_read_obj_ptr - like ckpt_read_obj_type, but discards header
 */
static int _ckpt_read(int fd, void *buf, int count)
{
	ssize_t nread;
	int nleft;

	for (nleft = count; nleft; nleft -= nread) {
		nread = read(fd, buf, nleft);
		if (nread < 0 && errno == EAGAIN)
			continue;
		if (nread == 0 && nleft == count)
			return 0;
		if (nread == 0)
			errno = EIO;
		if (nread <= 0)
			return -1;
		buf += nread;
	}
	return count;
}

static int ckpt_read(int fd, void *buf, int count)
{
	int ret;

	ret = _ckpt_read(fd, buf, count);
	if (ret == 0 && count) {
		errno = EINVAL;
		ret = -1;
	}
	return (ret < 0 ? ret : 0);
}

static int ckpt_read_obj(struct ckpt_ctx *ctx,
			 struct ckpt_hdr *h, void *buf, int n)
{
	int fd = ctx->args->infd;
	int ret;

	ret = ckpt_read(fd, h, sizeof(*h));
	if (ret < 0)
		return ret;
	if (h->len < sizeof(*h) || h->len > n)
		return ctx_ret_errno(ctx, EINVAL);
	if (h->len == sizeof(*h))
		return 0;
	return ckpt_read(fd, buf, h->len - sizeof(*h));
}

static int ckpt_read_obj_type(struct ckpt_ctx *ctx, void *buf, int n, int type)
{
	struct ckpt_hdr *h = (struct ckpt_hdr *) buf;
	int ret;

	ret = ckpt_read_obj(ctx, h, (void *) (h + 1), n);
	if (ret < 0)
		return ret;
	if (h->type != type)
		return ctx_ret_errno(ctx, EINVAL);
	return 0;
}

static int ckpt_read_obj_ptr(struct ckpt_ctx *ctx, void *buf, int n, int type)
{
	struct ckpt_hdr h;
	int ret;

	ret = ckpt_read_obj(ctx, &h, buf, n + sizeof(h));
	if (ret < 0)
		return ret;
	if (h.type != type)
		return ctx_ret_errno(ctx, EINVAL);
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
	    h->constants.uts_machine_len > BUFSIZE / 4)
		return ctx_ret_errno(ctx, EINVAL);

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

static int ckpt_read_container(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr_container *h;
	char *ptr;
	int ret;

	h = (struct ckpt_hdr_container *) ctx->container;
	ret = ckpt_read_obj_type(ctx, h, sizeof(*h), CKPT_HDR_CONTAINER);
	if (ret < 0)
		return ret;

	ptr = (char *) h;
	ptr += ((struct ckpt_hdr *) ptr)->len;
	ret = ckpt_read_obj_buffer(ctx, ptr, CHECKPOINT_LSM_NAME_MAX + 1);
	if (ret < 0)
		return ret;

	ptr += ((struct ckpt_hdr *) ptr)->len;
	return ckpt_read_obj_type(ctx, ptr, 200, CKPT_HDR_LSM_INFO);
}

static int ckpt_read_pids(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr_pids *h;
	int len, ret;

	h = (struct ckpt_hdr_pids *) ctx->pids;
	ret = ckpt_read_obj_type(ctx, h, sizeof(*h), CKPT_HDR_PIDS);
	if (ret < 0)
		return ret;

	ckpt_dbg("number of pids %d, vpids %d\n", h->nr_pids, h->nr_vpids);

	if (h->nr_pids <= 0) {
		ckpt_err("invalid number of pids %d", h->nr_pids);
		return ctx_ret_errno(ctx, EINVAL);
	}
	if (h->nr_vpids < 0) {
		ckpt_err("invalid number of vpids %d", h->nr_vpids);
		return ctx_ret_errno(ctx, EINVAL);
	}
	if (h->offset < 0) {
		ckpt_err("invalid pid offset %d", h->offset);
		return ctx_ret_errno(ctx, EINVAL);
	}

	ctx->pids_nr = h->nr_pids;
	ctx->vpids_nr = h->nr_vpids;
	ctx->pid_offset = h->offset - 1;

        len = ctx->pids_nr * sizeof(struct ckpt_pids) +
		ctx->vpids_nr * sizeof(__s32);

	ctx->pids_arr = malloc(len);
	ctx->pids_copy = malloc(len);
	ctx->pids_new = malloc(len);
	if (!ctx->pids_arr || !ctx->pids_copy || !ctx->pids_new)
		return ctx_ret_errno(ctx, EINVAL);

	ctx->pids_off = 0;
	ctx->pids_len = len;

	ret = ckpt_read_obj_ptr(ctx, ctx->pids_arr, len, CKPT_HDR_BUFFER);
	if (ret < 0)
		return ret;

	return ret;
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
		return ctx_ret_errno(ctx, EINVAL);
	}

	ctx->tasks_nr = h->nr_tasks;

	len = sizeof(struct ckpt_task_pids) * ctx->tasks_nr;

	ctx->tasks_arr = malloc(len);
	if (!ctx->tasks_arr)
		return ctx_ret_errno(ctx, EINVAL);

	ret = ckpt_read_obj_ptr(ctx, ctx->tasks_arr, len, CKPT_HDR_BUFFER);

	if (ret < 0)
		return ret;

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

static int ckpt_write_container(struct ckpt_ctx *ctx)
{
	char *ptr;
	int ret;

	ptr = (char *) ctx->container;
	/* write the container info section */
	ret = ckpt_write_obj(ctx, (struct ckpt_hdr *) ptr);
	if (ret < 0)
		return ret;

	/* write the lsm name buffer */
	ptr += ((struct ckpt_hdr *) ptr)->len;
	ret = ckpt_write_obj(ctx, (struct ckpt_hdr *) ptr);
	if (ret < 0)
		return ret;

	/* write the lsm policy section */
	ptr += ((struct ckpt_hdr *) ptr)->len;
	return ckpt_write_obj(ctx, (struct ckpt_hdr *) ptr);
}

static int ckpt_write_pids(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr_pids *h;
	int len;

	h = (struct ckpt_hdr_pids *) ctx->pids;
	if (ckpt_write_obj(ctx, (struct ckpt_hdr *) h) < 0)
		ckpt_abort(ctx, "write pids");

        len = ctx->pids_nr * sizeof(struct ckpt_pids) +
		ctx->vpids_nr * sizeof(__s32);
	if (ckpt_write_obj_ptr(ctx, ctx->pids_arr, len, CKPT_HDR_BUFFER) < 0)
		ckpt_abort(ctx, "write pids");

	return 0;
}

static int ckpt_write_tree(struct ckpt_ctx *ctx)
{
	struct ckpt_hdr_tree *h;
	int len;

	h = (struct ckpt_hdr_tree *) ctx->tree;
	if (ckpt_write_obj(ctx, (struct ckpt_hdr *) h) < 0)
		ckpt_abort(ctx, "write tree");

	len = sizeof(struct ckpt_task_pids) * ctx->tasks_nr;
ckpt_dbg("len = %d\n");
	if (ckpt_write_obj_ptr(ctx, ctx->tasks_arr, len, CKPT_HDR_BUFFER) < 0)
		ckpt_abort(ctx, "write pids");

	for (len = 0; len < ctx->tasks_nr; len++) {
		struct ckpt_task_pids *task;
		task = &ctx->tasks_arr[len];
		ckpt_dbg("\t[%d] pid %d tgid %d pgid %d sid %d\n", len,
			 task->vpid, task->vtgid, task->vpgid, task->vsid);
	}

	return 0;
}

/*
 * a simple hash implementation
 */

#define HASH_BITS	11
#define HASH_BUCKETS	(2 << (HASH_BITS - 1))

static int hash_expand(struct ckpt_ctx *ctx, int depth)
{
	struct hashent ***hash;
	int *hash_last_pid;

	hash = ctx->hash_arr;
	hash = realloc(hash, sizeof(*hash) * depth);
	if (!hash) {
		ckpt_perror("allocate hash table");
		return ctx_set_errno(ctx);
	} else
		ctx->hash_arr = hash;

	hash_last_pid = ctx->hash_last_pid;
	hash_last_pid =	realloc(hash_last_pid, sizeof(*hash_last_pid) * depth);
	if (!hash_last_pid) {
		ckpt_perror("allocate hash table");
		return ctx_set_errno(ctx);
	} else
		ctx->hash_last_pid = hash_last_pid;

	while (ctx->hash_depth < depth) {
		hash[ctx->hash_depth] = malloc(sizeof(**hash) * HASH_BUCKETS);
		if (!hash[ctx->hash_depth]) {
			ckpt_perror("allocate hash table");
			return ctx_set_errno(ctx);
		}
		memset(hash[ctx->hash_depth], 0, sizeof(**hash) * HASH_BUCKETS);
		hash_last_pid[ctx->hash_depth] = CKPT_RESERVED_PIDS;
		ctx->hash_depth++;
	}

	return 0;
}

static int hash_init(struct ckpt_ctx *ctx)
{
	return hash_expand(ctx, 1);
}

static void hash_exit(struct ckpt_ctx *ctx)
{
	struct hashent *hash, *next;
	int i, j;

	if (!ctx->hash_arr)
		return;

	for (i = 0; i < ctx->hash_depth; i++) {
		for (j = 0; j < HASH_BUCKETS; j++) {
			for (hash = ctx->hash_arr[i][i]; hash; hash = next) {
				next = hash->next;
				free(hash);
			}
		}
		free(ctx->hash_arr[i]);
	}

	free(ctx->hash_last_pid);
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

static int hash_insert(struct ckpt_ctx *ctx, long key, void *data, int level)
{
	struct hashent *hash;
	int bucket;

	if (level >= ctx->hash_depth)
		if (hash_expand(ctx, level) < 0)
			return ctx_set_errno(ctx);

	hash = malloc(sizeof(*hash));
	if (!hash) {
		ckpt_perror("malloc hash");
		return ctx_set_errno(ctx);
	}
	hash->key = key;
	hash->data = data;

	bucket = hash_func(key);
	hash->next = ctx->hash_arr[level][bucket];
	ctx->hash_arr[level][bucket] = hash;

	return 0;
}

static void *hash_lookup_level(struct ckpt_ctx *ctx, long key, int level)
{
	struct hashent *hash;
	int bucket;

	if (level > ctx->hash_depth)
		return NULL;

	bucket = hash_func(key);
	for (hash = ctx->hash_arr[level][bucket]; hash; hash = hash->next) {
		if (hash->key == key)
			return hash->data;
	}
	return NULL;
}

static void *hash_lookup(struct ckpt_ctx *ctx, long key)
{
	return hash_lookup_level(ctx, key, 0);
}

static void *hash_lookup_ind(struct ckpt_ctx *ctx, int n)
{
	if (n == 0 || n == CKPT_PID_ROOT)
		return hash_lookup_level(ctx, pid_at_index(ctx, 1), 0);
	else
		return hash_lookup_level(ctx, pid_at_index(ctx, n), 0);
}
