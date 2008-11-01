#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
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

struct cr_ctx {
	int fd;
	pid_t pid;
	int tasks_nr;
	struct cr_hdr_pids *tasks_arr;
};

static int cr_read(struct cr_ctx *ctx, void *buf, int count);
static int cr_read_obj(struct cr_ctx *ctx, struct cr_hdr *h, void *buf, int n);
static int cr_read_obj_type(struct cr_ctx *ctx, void *buf, int n, int type);

static int cr_read_head(struct cr_ctx *ctx);
static int cr_read_tree(struct cr_ctx *ctx);
static int cr_make_tree(struct cr_ctx *ctx, pid_t pid, int pos);

int main(int argc, char *argv[])
{
	struct cr_ctx ctx;
	int ret;

	memset(&ctx, 0, sizeof(ctx));

	ctx.fd = STDIN_FILENO;
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

	ret = cr_make_tree(&ctx, getpid(), 0);

	/* should not return ... */

	perror("make c/r tree");
	return 1;
}

/*
 * low-level read from checkpoint image
 *   cr_read - read 'count' bytes to 'buf'
 *   cr_read_obj - read up to 'n' bytes of object into 'buf'
 *   cr_read_type - read up to 'n' bytes of object type 'type' into 'buf'
 */
static int cr_read(struct cr_ctx *ctx, void *buf, int count)
{
	ssize_t nread;
	int nleft;

	for (nleft = count; nleft; nleft -= nread) {
		nread = read(ctx->fd, buf, nleft);
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

	ret = cr_read(ctx, h, sizeof(*h));
	if (ret < 0)
		return ret;
	if (h->len < 0 || h->len > n)
		return -EINVAL;
	return cr_read(ctx, buf, h->len);
}

static int cr_read_obj_type(struct cr_ctx *ctx, void *buf, int n, int type)
{
	struct cr_hdr h;
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
	struct cr_hdr_head hh;
	int parent;

	parent = cr_read_obj_type(ctx, &hh, sizeof(hh), CR_HDR_HEAD);
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
	struct cr_hdr_tree hh;
	int parent, ret;

	parent = cr_read_obj_type(ctx, &hh, sizeof(hh), CR_HDR_TREE);
	if (parent < 0)
		return parent;
	else if (parent != 0) {
		errno = EINVAL;
		return -1;
	}

	cr_dbg("number of tasks: %d\n", hh.nr_tasks);

	if (hh.nr_tasks <= 0) {
		cr_err("invalid number of tasks %d", hh.nr_tasks);
		return -1;
	}

	ctx->tasks_nr = hh.nr_tasks;
	ctx->tasks_arr = malloc(sizeof(*ctx->tasks_arr) * ctx->tasks_nr);

	if (!ctx->tasks_arr)
		return -1;

	ret = cr_read(ctx, ctx->tasks_arr,
		      sizeof(*ctx->tasks_arr) * ctx->tasks_nr);
	return ret;
}

/*
 * create tasks tree
 */
static int cr_make_tree(struct cr_ctx *ctx, pid_t pid, int pos)
{
	pid_t parent;
	pid_t child;
	int first;

	first = pos;

	while (pos < ctx->tasks_nr) {
		parent = ctx->tasks_arr[pos++].parent;
		if (parent != pid)
			continue;

		cr_dbg("forking entry[%d].vpid = %d\n",
		       pos, ctx->tasks_arr[pos-1].vpid);

		child = fork();
		switch (child) {
		case -1:
			return -1;
		case 0:
			return cr_make_tree(ctx, getpid(), pos);
		default:
			break;
		}
	}

	/* on success this doesn't return */
	cr_dbg("about to call sys_restart()\n");
	return restart(ctx->pid, ctx->fd, 0);
}
