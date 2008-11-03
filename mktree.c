#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <asm/unistd.h>
#include <sys/syscall.h>

#include <linux/checkpoint_hdr.h>

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
	int in;
	int out;
	pid_t pid;
	int tasks_nr;
	int tasks_new;
	int tasks_sav;
	struct cr_hdr_pids *pids_arr;
	struct cr_hdr_pids *pids_new;
	struct cr_hdr_pids *pids_sav;
	char buf[BUFSIZE];
};

static int cr_write(int fd, void *buf, int count);
static int cr_write_obj(struct cr_ctx *ctx, struct cr_hdr *h, void *buf);

static int cr_read(int fd, void *buf, int count);
static int cr_read_obj(struct cr_ctx *ctx, struct cr_hdr *h, void *buf, int n);
static int cr_read_obj_type(struct cr_ctx *ctx, void *buf, int n, int type);

static int cr_read_head(struct cr_ctx *ctx);
static int cr_read_tree(struct cr_ctx *ctx);
static int cr_make_tree(struct cr_ctx *ctx, pid_t pid, int pos);

static int cr_feeder(struct cr_ctx *ctx);
static void cr_abort(struct cr_ctx *ctx, char *str);

struct pid_swap {
	pid_t old;
	pid_t new;
};

int pipefd[4];

int main(int argc, char *argv[])
{
	struct cr_ctx ctx;
	int ret;

	if (pipe(&pipefd[0]) < 0 || pipe(&pipefd[2])) {
		perror("pipe");
		exit(1);
	}

	memset(&ctx, 0, sizeof(ctx));

	ctx.in = STDIN_FILENO;

	ctx.pid = getpid();

	ret = cr_read_head(&ctx);
	if (ret < 0) {
		perror("read c/r head");
		exit(1);
	}
		
	ret = cr_read_tree(&ctx);
	if (ret < 0) {
		perror("read c/r tree");
		exit(1);
	}

	switch (fork()) {
	case -1:
		perror("fork");
		exit(1);
	case 0:
		/* should not return ... */
		setpgrp();
		ctx.pid = getpid();
		close(pipefd[0]);
		close(pipefd[3]);
		dup2(pipefd[2], STDIN_FILENO);
		ret = cr_make_tree(&ctx, ctx.pids_arr[0].vpid, 0);
		cr_dbg("c/r make tree failed ?\n");
		exit(1);
	default:
		break;
	}

	close(pipefd[1]);
	close(pipefd[2]);

	ctx.out = pipefd[3];

	ret = cr_feeder(&ctx);
	cr_dbg("c/r done (%d)\n", ret);

	return ret;
}

/*
 * low-level write to pipe
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

	ret = cr_write(ctx->out, h, sizeof(*h));
	if (ret < 0)
		return ret;
	return cr_write(ctx->out, buf, h->len);
}

/*
 * low-level read from checkpoint image
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

	ret = cr_read(ctx->in, h, sizeof(*h));
	if (ret < 0)
		return ret;
	if (h->len < 0 || h->len > n)
		return -EINVAL;
	return cr_read(ctx->in, buf, h->len);
}

static int cr_read_obj_type(struct cr_ctx *ctx, void *buf, int n, int type)
{
	struct cr_hdr *h = (struct cr_hdr *) ctx->buf;
	int ret;

	ret = cr_read_obj(ctx, &h, buf, n);
	if (ret < 0)
		return ret;
	if (h.type == type)
		ret = h.parent;
	else
		ret = -1;
	return ret;
}

/*
 * parse the checkpoint image
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

static int cr_read_tree(struct cr_ctx *ctx)
{
	struct cr_hdr *h = (struct cr_hdr *) ctx->buf;
	struct cr_hdr_tree *hh = (struct cr_hdr_tree *) (h + 1);
	int parent, ret;

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

	ctx->tasks_nr = hh->tasks_nr;
	ctx->pids_arr = malloc(sizeof(*ctx->pids_arr) * ctx->tasks_nr);

	if (!ctx->pids_arr)
		return -1;

	ret = cr_read(ctx->in, ctx->pids_arr,
		      sizeof(*ctx->pids_arr) * ctx->tasks_nr);
	return ret;
}

/*
 * write the checkpoint image
 */

static int cr_write_head(struct cr_ctx *ctx)
{
	struct cr_hdr *h;
	struct cr_hdr_head *hh;

	h = (struct cr_hdr *) ctx->buf;
	hh = (struct cr_hdr_head *) (h + 1);
	return cr_write_obj(ctx, h, hh);
}

static int cr_write_tree(struct cr_ctx *ctx)
{
	struct cr_hdr *h;
	struct cr_hdr_head *hh;

	h = (struct cr_hdr *) ctx->buf;
	hh = (struct cr_hdr_head *) (h + 1);
	if (cr_write_obj(ctx, h, hh) < 0)
		cr_abort(ctx, "write tree");

	if (cr_write(ctx->out, ctx->pids_new,
		     sizeof(*ctx->pids_new) * ctx->tasks_nr) < 0)
		cr_abort(ctx, "write pids_new");

	return 0;
}


/*
 * create tasks tree
 */
static int cr_make_tree(struct cr_ctx *ctx, pid_t pid, int pos)
{
	struct pid_swap swap;
	pid_t parent;
	pid_t child;
	int first, ret;

	first = pos;

	/* communicate via pipe that all is well */
	swap.old = pid;
	swap.new = getpid();
	ret = write(pipefd[1], &swap, sizeof(swap));
	if (ret != sizeof(swap)) {
		perror("write swap");
		exit(1);
	}

	while (pos < ctx->tasks_nr) {
		parent = ctx->pids_arr[pos++].parent;
		if (parent != pid)
			continue;

		cr_dbg("forking entry[%d].vpid = %d\n",
		       pos, ctx->pids_arr[pos - 1].vpid);

		child = fork();
		switch (child) {
		case -1:
			return -1;
		case 0:
			pid = ctx->pids_arr[pos - 1].vpid;
			return cr_make_tree(ctx, pid, pos);
		default:
			break;
		}
	}

	/* on success this doesn't return */
	cr_dbg("about to call sys_restart()\n");
	return restart(ctx->pid, ctx->in, 0);
}

static void cr_abort(struct cr_ctx *ctx, char *str)
{
	perror(str);
	kill(-(ctx->pid), SIGTERM);
	exit(1);
}

static int cr_feeder(struct cr_ctx *ctx)
{
	struct pid_swap swap;
	int n, m, ret;

	ctx->pids_new = malloc(sizeof(*ctx->pids_arr) * ctx->tasks_nr);
	if (!ctx->pids_new)
		cr_abort(ctx, "malloc");

	ctx->tasks_new = ctx->tasks_nr;
	ctx->tasks_sav = ctx->tasks_nr;

	ctx->pids_sav = ctx->pids_arr;
	memcpy(ctx->pids_new, ctx->pids_sav,
	       sizeof(*ctx->pids_arr) * ctx->tasks_nr);

	for (n = 0; n < ctx->tasks_nr; n++) {
		ret = read(pipefd[0], &swap, sizeof(swap));
		if (ret < 0)
			cr_abort(ctx, "read pipe");
		cr_dbg("c/r swap old %d new %d\n", swap.old, swap.new);
		for (m = 0; m < ctx->tasks_nr; m++) {
			if (ctx->pids_new[m].vpid == swap.old)
				ctx->pids_new[m].vpid = swap.new;
			if (ctx->pids_new[m].vtgid == swap.old)
				ctx->pids_new[m].vtgid = swap.new;
			if (ctx->pids_new[m].parent == swap.old)
				ctx->pids_new[m].parent = swap.new;
		}
	}

	close(pipefd[0]);

	/* read head -> and write */
	if (cr_read_head(ctx) < 0)
		cr_abort(ctx, "read c/r head");
	if (cr_write_head(ctx) < 0)
		cr_abort(ctx, "write c/r head");

	/* read tree -> and write modified tree */
	if (cr_read_tree(ctx) < 0)
		cr_abort(ctx, "read c/r tree");

	if (ctx->tasks_nr != ctx->tasks_sav)
		cr_abort(ctx, "tasks_nr mismatch");
	for (n = 0; n < ctx->tasks_nr; n++) {
		if (ctx->pids_arr[n].vpid != ctx->pids_sav[n].vpid ||
		    ctx->pids_arr[n].vtgid != ctx->pids_sav[n].vtgid ||
		    ctx->pids_arr[n].parent != ctx->pids_sav[n].parent)
			cr_abort(ctx, "pids_arr mismatch");
	}
	if (cr_write_tree(ctx) < 0)
		cr_abort(ctx, "write c/r tree");

	/* read rest -> write rest */
	while (1) {
		ret = read(STDIN_FILENO, ctx->buf, BUFSIZE);
		cr_dbg("c/r read input %d\n", ret);
		if (ret == 0)
			break;
		if (ret < 0)
			cr_abort(ctx, "read input");
		ret = cr_write(pipefd[3], ctx->buf, ret);
		if (ret < 0)
			cr_abort(ctx, "write output");
	}

	return 0;
}
