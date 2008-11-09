/*
 *  mktree.c: restart of multiple processes
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
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <sys/syscall.h>

#include <linux/checkpoint_hdr.h>

#define _GNU_SOURCE
#include <getopt.h>
#undef _GNU_SOURCE

static char usage_str[] =
"usage: mktree [opts]\n"
"  mktree restores from a checkpoint image by first creating in userspace\n"
"  the original tasks tree, and then calling sys_restart by each task.\n"
"\tOptions:\n"
"\t -h,--help             print this help message\n"
"\t -p,--pids             restore original tasks' pids (in container)\n"
"\t -P,--no-pids          do not restore original tasks' pids\n"
"";

/*
 * 'mktree' has two modes of operation:
 *
 * (1) with pids (default): assumes that original pids from the time of the
 *   checkpoint are restored. For this, 'mktree' must be the init task of a
 *   fresh container. (Also requires a method to clone-with-pid).
 *
 * (2) no-pids: creates an equivalent tree without restoring the original
 *   pids, assuming that the application can tolerate this. For this, the
 *   'cr_hdr_pids' array is transformed on-the-fly before it is handed to
 *   the restart syscall (using a helper process).
 */

#ifdef CHECKPOINT_DEBUG
#define cr_dbg(format, args...)  \
	fprintf(stderr, "[%d]" format, getpid(), ##args)
#endif

#define cr_err(...)  \
	fprintf(stderr, __VA_ARGS__)

inline static int restart(int crid, int fd, unsigned long flags)
{
	return syscall(__NR_restart, crid, fd, flags);
}

#define BUFSIZE  (4 * 4096)

struct cr_ctx {
	pid_t init_pid;
	int pipe_in;
	int pipe_out;
	int pids_nr;
	struct cr_hdr_pids *pids_arr;
	char buf[BUFSIZE];
	struct args *args;
};

static int cr_mktree_pids(struct cr_ctx *ctx);
static int cr_mktree_nopids(struct cr_ctx *ctx);
static int cr_make_tree(struct cr_ctx *ctx, pid_t pid, int pos);

static void cr_abort(struct cr_ctx *ctx, char *str);
static int cr_feeder(struct cr_ctx *ctx);
static int cr_write(int fd, void *buf, int count);
static int cr_write_obj(struct cr_ctx *ctx, struct cr_hdr *h, void *buf);

static int cr_write_head(struct cr_ctx *ctx);
static int cr_write_tree(struct cr_ctx *ctx,
			 struct cr_hdr_pids *pids_arr, int pids_nr);

static int cr_read(int fd, void *buf, int count);
static int cr_read_obj(struct cr_ctx *ctx, struct cr_hdr *h, void *buf, int n);
static int cr_read_obj_type(struct cr_ctx *ctx, void *buf, int n, int type);

static int cr_read_head(struct cr_ctx *ctx);
static int cr_read_tree(struct cr_ctx *ctx,
			struct cr_hdr_pids **pids_arr, int *pids_nr);

struct pid_swap {
	pid_t old;
	pid_t new;
};

struct args {
	int pids;
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
		{ "no-pids",	no_argument,		NULL, 'P' },
		{ "pids",	no_argument,		NULL, 'p' },
		{ NULL,		0,			NULL, 0 }
	};
	static char optc[] = "hpPv";

	/* defaults */
	args->pids = 1;

	while (1) {
		int c = getopt_long(argc, argv, optc, opts, NULL);
		if (c == -1)
			break;
		switch (c) {
		case '?':
			exit(1);
		case 'h':
			usage(usage_str);
		case 'p':
			args->pids = 1;
			break;
		case 'P':
			args->pids = 0;
			break;
		default:
			usage(usage_str);
		}
	}
}

int main(int argc, char *argv[])
{
	struct cr_ctx ctx;
	struct args args;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	memset(&args, 0, sizeof(args));

	parse_args(&args, argc, argv);

	ctx.init_pid = getpid();
	ctx.args = &args;

	setpgrp();

	ret = cr_read_head(&ctx);
	if (ret < 0) {
		perror("read c/r head");
		exit(1);
	}
		
	ret = cr_read_tree(&ctx, &ctx.pids_arr, &ctx.pids_nr);
	if (ret < 0) {
		perror("read c/r tree");
		exit(1);
	}

	if (args.pids)
		ret = cr_mktree_pids(&ctx);
	else
		ret = cr_mktree_nopids(&ctx);

	cr_dbg("c/r make tree failed ?\n");
	return 1;
}

static int cr_mktree_pids(struct cr_ctx *ctx)
{
	return cr_make_tree(ctx, getpid(), 0);
}

/* else - no need to 'restore' original pids */
static int cr_mktree_nopids(struct cr_ctx *ctx)
{
	int pipe_child[2];	/* children report status */
	int pipe_feed[2];	/* feeder provides input */
	int status, ret;
	pid_t pid;

	if (pipe(&pipe_child[0]) < 0 || pipe(&pipe_feed[0])) {
		perror("pipe");
		exit(1);
	}

	switch ((pid = fork())) {
	case -1:
		perror("fork");
		exit(1);
	default:
		/* child pipe */
		close(pipe_child[0]);
		ctx->pipe_out = pipe_child[1];
		/* feeder pipe */
		close(pipe_feed[1]);
		if (pipe_feed[0] != STDIN_FILENO) {
			dup2(pipe_feed[0], STDIN_FILENO);
			close(pipe_feed[0]);
		}
		/* collect child */
		ret = waitpid(pid, &status, 0);
		if (ret < 0) {
			perror("pipe");
			exit(1);
		} else if (WIFSIGNALED(status)) {
			fprintf(stderr, "feeder terminated with signal %d\n",
				WTERMSIG(status));
			exit(1);
		} else if (WEXITSTATUS(status) != 0) {
			fprintf(stderr, "feeder exited with bad status %d\n",
				WEXITSTATUS(status));
			exit(1);
		}
		/* won't return if all goes well */
		ret = cr_make_tree(ctx, ctx->pids_arr[0].vpid, 0);
		break;
	case 0:
		/* fork again so we don't need to be collected later */
		if ((pid = fork()) < 0) {
			perror("fork");
			exit(1);
		} else if (pid > 0) {
			exit(0);
		}
		/* child pipe */
		close(pipe_child[1]);
		ctx->pipe_in = pipe_child[0];
		/* feeder pipe */
		close(pipe_feed[0]);
		if (pipe_feed[1] != STDOUT_FILENO) {
			dup2(pipe_feed[1], STDOUT_FILENO);
			close(pipe_feed[1]);
		}
		/* won't return if all goes well */
		ret = cr_feeder(ctx);
		break;
	}

	return ret;
}


/*
 * cr_make_tree - create the tasks tree by recursively following the
 * "instruction" give in the 'struct cr_hdr_pids' array
 *
 * @pid is our own pid
 * @pos is the current position in the array 
 */
static int cr_make_tree(struct cr_ctx *ctx, pid_t pid, int pos)
{
	struct pid_swap swap;
	pid_t child;
	int ret;

	while (pos < ctx->pids_nr) {
		/* skip if this is not my child */
		if (ctx->pids_arr[pos++].vppid != pid)
			continue;

		cr_dbg("forking entry[%d].vpid = %d\n",
		       pos, ctx->pids_arr[pos - 1].vpid);

		child = fork();
		switch (child) {
		case -1:
			return -1;
		case 0:
			/* child proceeds recursively from @pos */
			pid = ctx->pids_arr[pos - 1].vpid;
			return cr_make_tree(ctx, pid, pos);
		default:
			break;
		}
	}

	/* in 'no-pids' mode we need to report old/new pids via pipe */

	if (!ctx->args->pids) {
		/* communicate via pipe that all is well */
		swap.old = pid;
		swap.new = getpid();
		ret = write(ctx->pipe_out, &swap, sizeof(swap));
		if (ret != sizeof(swap)) {
			perror("write swap");
			exit(1);
		}
		close(ctx->pipe_out);
	}

	/* on success this doesn't return */
	cr_dbg("about to call sys_restart()\n");
	ret = restart(ctx->init_pid, STDIN_FILENO, 0);
	if (ret < 0)
		perror("restart");
	return ret;
}

static void cr_abort(struct cr_ctx *ctx, char *str)
{
	perror(str);
	kill(-(ctx->init_pid), SIGTERM);
	exit(1);
}

/*
 * Helper process to read in checkpoint image, transform the pids
 * array, struct cr_hdr_pids, on the fly and feed the result to the
 * "init" task of the restart 
 *
 * First, collect pids reported by the newly created tasks; each task
 * sends a 'struct pid_swap' indicating old- and new-pid. Modify a
 * copy of the pids array accordingly.
 *
 * Second, read in the checkpoint header (cr_hdr_head), and promptly
 * write it on the output.
 *
 * Third, read the task tree (cr_hdr_tree) and then, after verifying
 * that it is consistent with the original task tree previously read,
 * write the _modified_ pids array instead of the original.
 *
 * Finally, pass on the rest of the data by reading in chunks and
 * then writing them on the output.
 */
static int cr_feeder(struct cr_ctx *ctx)
{
	struct pid_swap swap;
	struct cr_hdr_pids *pids_new;
	struct cr_hdr_pids *pids_sav;
	int pids_nr;
	int n, m, ret;

	/* make a copy of the pids_arr */
	pids_nr = ctx->pids_nr;
	pids_new = malloc(sizeof(*pids_new) * pids_nr);
	if (!pids_new)
		cr_abort(ctx, "malloc");
	memcpy(pids_new, ctx->pids_arr, sizeof(*pids_new) * pids_nr);

	/* read in 'pid_swap' data and adjust pids_new array */
	for (n = 0; n < pids_nr; n++) {
		ret = read(ctx->pipe_in, &swap, sizeof(swap));
		if (ret < 0)
			cr_abort(ctx, "read pipe");
		cr_dbg("c/r swap old %d new %d\n", swap.old, swap.new);
		for (m = 0; m < pids_nr; m++) {
			if (pids_new[m].vpid == swap.old)
				pids_new[m].vpid = swap.new;
			if (pids_new[m].vtgid == swap.old)
				pids_new[m].vtgid = swap.new;
			if (pids_new[m].vppid == swap.old)
				pids_new[m].vppid = swap.new;
		}
	}

	close(ctx->pipe_in);

	/* read head -> and write */
	if (cr_read_head(ctx) < 0)
		cr_abort(ctx, "read c/r head");
	if (cr_write_head(ctx) < 0)
		cr_abort(ctx, "write c/r head");

	/* read tree again */
	pids_sav = ctx->pids_arr;
	if (cr_read_tree(ctx, &ctx->pids_arr, &ctx->pids_nr) < 0)
		cr_abort(ctx, "read c/r tree");

	/* verify that second tree is identical to saved one */
	if (ctx->pids_nr != pids_nr)
		cr_abort(ctx, "tasks_nr mismatch");
	for (n = 0; n < pids_nr; n++) {
		if (ctx->pids_arr[n].vpid != pids_sav[n].vpid ||
		    ctx->pids_arr[n].vtgid != pids_sav[n].vtgid ||
		    ctx->pids_arr[n].vppid != pids_sav[n].vppid)
			cr_abort(ctx, "pids_arr mismatch");
	}

	/* and write modified tree */
	if (cr_write_tree(ctx, pids_new, pids_nr) < 0)
		cr_abort(ctx, "write c/r tree");

	/* read rest -> write rest */
	while (1) {
		ret = read(STDIN_FILENO, ctx->buf, BUFSIZE);
		cr_dbg("c/r read input %d\n", ret);
		if (ret == 0)
			break;
		if (ret < 0)
			cr_abort(ctx, "read input");
		ret = cr_write(STDOUT_FILENO, ctx->buf, ret);
		if (ret < 0)
			cr_abort(ctx, "write output");
	}

	/* all is well - we are expected to terminate */
	exit(0);
}

/*
 * low-level write
 *   cr_write - write 'count' bytes to 'buf'
 *   cr_write_obj - write object
 */
static int cr_write(int fd, void *buf, int count)
{
	ssize_t nwrite;
	int nleft;

	for (nleft = count; nleft; nleft -= nwrite) {
		nwrite = write(fd, buf, nleft);
		if (nwrite < 0 && errno == -EAGAIN)
			continue;
		if (nwrite < 0)
			return -1;
		buf += nwrite;
	}
	return 0;
}

int cr_write_obj(struct cr_ctx *ctx, struct cr_hdr *h, void *buf)
{
	int ret;

	ret = cr_write(STDOUT_FILENO, h, sizeof(*h));
	if (ret < 0)
		return ret;
	return cr_write(STDOUT_FILENO, buf, h->len);
}

/*
 * low-level read
 *   cr_read - read 'count' bytes to 'buf'
 *   cr_read_obj - read up to 'n' bytes of object into 'buf'
 *   cr_read_type - read up to 'n' bytes of object type 'type' into 'buf'
 */
static int cr_read(int fd, void *buf, int count)
{
	ssize_t nread;
	int nleft;

	for (nleft = count; nleft; nleft -= nread) {
		nread = read(fd, buf, nleft);
		if (nread < 0 && errno == -EAGAIN)
			continue;
		if (nread <= 0)
			return -1;
		buf += nread;
	}
	return 0;
}

static int cr_read_obj(struct cr_ctx *ctx, struct cr_hdr *h, void *buf, int n)
{
	int ret;

	ret = cr_read(STDIN_FILENO, h, sizeof(*h));
	if (ret < 0)
		return ret;
	if (h->len < 0 || h->len > n)
		return -EINVAL;
	return cr_read(STDIN_FILENO, buf, h->len);
}

static int cr_read_obj_type(struct cr_ctx *ctx, void *buf, int n, int type)
{
	struct cr_hdr *h = (struct cr_hdr *) ctx->buf;
	int ret;

	ret = cr_read_obj(ctx, h, buf, n);
	if (ret < 0)
		return ret;
	if (h->type == type)
		ret = h->parent;
	else
		ret = -1;
	return ret;
}

/*
 * read/write the checkpoint image: similar to in-kernel code
 */

static int cr_read_head(struct cr_ctx *ctx)
{
	struct cr_hdr *h = (struct cr_hdr *) ctx->buf;
	struct cr_hdr_head *hh = (struct cr_hdr_head *) (h + 1);
	int parent;

	parent = cr_read_obj_type(ctx, hh, sizeof(*hh), CR_HDR_HEAD);
	if (parent < 0)
		return parent;
	else if (parent != 0) {
		errno = EINVAL;
		return -1;
	}

	/* FIXME: skip version validation for now */

	return 0;
}

static int cr_read_tree(struct cr_ctx *ctx,
			struct cr_hdr_pids **pids_arr, int *pids_nr)
{
	struct cr_hdr *h = (struct cr_hdr *) ctx->buf;
	struct cr_hdr_tree *hh = (struct cr_hdr_tree *) (h + 1);
	int parent;

	parent = cr_read_obj_type(ctx, hh, sizeof(*hh), CR_HDR_TREE);
	if (parent < 0)
		return parent;
	else if (parent != 0) {
		errno = EINVAL;
		return -1;
	}

	cr_dbg("number of tasks: %d\n", hh->tasks_nr);

	if (hh->tasks_nr <= 0) {
		cr_err("invalid number of tasks %d", hh->tasks_nr);
		return -1;
	}

	*pids_nr = hh->tasks_nr;
	*pids_arr = malloc(sizeof(**pids_arr) * (*pids_nr));
	if (!*pids_arr)
		return -1;

	return cr_read(STDIN_FILENO, *pids_arr,
		       sizeof(**pids_arr) * (*pids_nr));
}

static int cr_write_head(struct cr_ctx *ctx)
{
	struct cr_hdr *h;
	struct cr_hdr_head *hh;

	h = (struct cr_hdr *) ctx->buf;
	hh = (struct cr_hdr_head *) (h + 1);
	return cr_write_obj(ctx, h, hh);
}

static int cr_write_tree(struct cr_ctx *ctx,
			 struct cr_hdr_pids *pids_arr, int pids_nr)
{
	struct cr_hdr *h;
	struct cr_hdr_head *hh;

	h = (struct cr_hdr *) ctx->buf;
	hh = (struct cr_hdr_head *) (h + 1);
	if (cr_write_obj(ctx, h, hh) < 0)
		cr_abort(ctx, "write tree");

	if (cr_write(STDOUT_FILENO, pids_arr, sizeof(*pids_arr) * pids_nr) < 0)
		cr_abort(ctx, "write pids");

	return 0;
}
