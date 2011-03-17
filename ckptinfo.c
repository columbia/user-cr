/*
 *  ckptinfo.c: provide information about a checkpoint image
 *
 *  Copyright (C) 2009 Oren Laadan
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <linux/checkpoint_hdr.h>
#include <asm/checkpoint_hdr.h>

static char usage_str[] =
"usage: ckptinfo [opts] [IMAGE]\n"
"  'ckptinfo' takes a checkpoint image, and shows information about it.\n"
"\n"
"\tOptions:\n"
"\t -h,--help             print this help message\n"
"\t -e,--error            show error messages\n"
"\t -p,--pids             show the process tree\n"
"\t -v,--verbose          verbose output\n"
"\t    --show-arch-regs   show registers contents\n"
"";

struct args {
	int error;
	int verbose;
	int show_arch_regs;
	int show_task_tree;
};

int __verbose;
unsigned long __filepos;

#define VERBOSE(_format, _args...)			\
	do {						\
		if (__verbose)				\
			printf(_format, ##_args);	\
	} while (0)

static int __image_read(int fd, void *buf, int len);
static int image_read_obj(int fd, struct ckpt_hdr **h);

static int image_parse(int fd, struct args *args);
static int image_parse_vma(struct ckpt_hdr *h, int fd, struct args *args);
static int image_parse_file(struct ckpt_hdr *h, int fd, struct args *args);
static int image_parse_objref(struct ckpt_hdr *h, int fd, struct args *args);
static int image_parse_tree(struct ckpt_hdr *h, int fd, struct args *args);
static int image_parse_error(struct ckpt_hdr *h, int fd, struct args *args);

#ifdef __i386__
#define __HAVE_image_parse_cpu
#define image_parse_cpu   image_parse_cpu_X86
static int image_parse_cpu_X86(struct ckpt_hdr *h, int fd, struct args *args);
#elif defined(__s390__) || defined(__s390x__)
#define __HAVE_image_parse_cpu
#define image_parse_cpu   image_parse_cpu_s390
static int image_parse_cpu_s390(struct ckpt_hdr *h, int fd, struct args *args);
#else
static int image_parse_cpu(struct ckpt_hdr *h, int fd, struct args *args);
#endif

char *hdr_to_str(int type);
char *obj_to_str(int type);
char *file_to_str(int type);
char *vma_to_str(int type);

static void usage(char *str)
{
	fprintf(stderr, "%s", str);
	exit(1);
}

static void parse_args(struct args *args, int argc, char *argv[])
{
	static struct option opts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "error",	no_argument,		NULL, 'e' },
		{ "verbose",	no_argument,		NULL, 'v' },
		{ "pids-only",	no_argument,		NULL, 'p' },
		{ "show-arch-regs",	no_argument,	NULL, 1 },
		{ NULL,		0,			NULL, 0 }
	};
	static char optc[] = "hvep";

	while (1) {
		int c = getopt_long(argc, argv, optc, opts, NULL);
		if (c == -1)
			break;
		switch (c) {
		case '?':
			exit(1);
		case 'h':
			usage(usage_str);
		case 'e':
			args->error = 1;
			break;
		case 'p':
			args->show_task_tree = 1;
			break;
		case 'v':
			args->verbose = 1;
			break;
		case 1:
#ifndef __HAVE_image_parse_cpu
			printf("Warning: --show-arch-regs unsupported on architecture\n");
#endif
			args->show_arch_regs = 1;
			break;
		default:
			usage(usage_str);
		}
	}
}

int main(int argc, char *argv[])
{
	struct args args;
	char *image;
	int fd, ret;

	memset(&args, 0, sizeof(args));
	parse_args(&args, argc, argv);

	if (args.verbose)
		__verbose = 1;

	argc -= optind;

	if (argc == 0) {
		fd = STDIN_FILENO;
	} else if (argc == 1) {
		image = argv[optind];
		fd = open(image, O_RDONLY);
		if (fd < 0) {
			perror(image);
			exit(1);
		}
	} else {
		usage(usage_str);
	}

	ret = image_parse(fd, &args);
	return (ret < 0 ? 1 : 0);
}

static int __image_read(int fd, void *buf, int len)
{
	ssize_t nread = 0;
	int nleft;

	for (nleft = len; nleft; nleft -= nread) {
		nread = read(fd, buf, nleft);
		if (nread < 0 && ((errno == EAGAIN) || (errno == EINTR))) {
			nread = 0;
			continue;
		}
		if (nread <= 0)
			break;
		buf += nread;
	}

	if (nread < 0) {
		perror("read from image");
		return -1;
	}

	if (nleft) {
		fprintf(stderr, "unexpected end of file (read %d of %d)\n",
			len - nleft, len);
		return -1;
	}

	__filepos += len;
	return len;
}

static int image_read_obj(int fd, struct ckpt_hdr **hh)
{
	struct ckpt_hdr h, *p = NULL;
	int ret;

	ret = __image_read(fd, &h, sizeof(h));
	if (ret <= 0)
		return ret;

	VERBOSE("info: [@%lu] object %3d %s len %d\n",
		__filepos, h.type, hdr_to_str(h.type), h.len);

	p = malloc(h.len);
	if (!p) {
		fprintf(stderr, "malloc of %d failed\n", h.len);
		return -1;
	}

	*p = h;

	ret = __image_read(fd, (p + 1), h.len - sizeof(h));
	if (ret < 0) {
		fprintf(stderr, "read of image failed\n");
		free(p);
		return -1;
	}

	*hh = p;
	return h.len;
}

static int image_parse(int fd, struct args *args)
{
	struct ckpt_hdr *h;
	int ret;

	do {
		ret = image_read_obj(fd, &h);
		if (ret <= 0)
			break;
		if (!h)
			continue;
		switch (h->type) {
		case CKPT_HDR_OBJREF:
			ret = image_parse_objref(h, fd, args);
			break;
		case CKPT_HDR_TREE:
			ret = image_parse_tree(h, fd, args);
			break;
		case CKPT_HDR_FILE:
			ret = image_parse_file(h, fd, args);
			break;
		case CKPT_HDR_VMA:
			ret = image_parse_vma(h, fd, args);
			break;
		case CKPT_HDR_CPU:
			ret = image_parse_cpu(h, fd, args);
			break;
		case CKPT_HDR_ERROR:
			ret = image_parse_error(h, fd, args);
			break;
		}
		free(h);
	} while (ret > 0);

	return ret;
}

static int image_parse_tree(struct ckpt_hdr *h, int fd, struct args *args)
{
	struct ckpt_hdr_tree *hh;
	struct ckpt_task_pids *pp;
	int nr_tasks;
	int i, ret;

	hh = (struct ckpt_hdr_tree *) h;
	nr_tasks = hh->nr_tasks;
	free(h);

	ret = image_read_obj(fd, &h);
	if (ret == 0)
		fprintf(stderr, "process tree: unexpected end of file");
	if (ret <= 0)
		return -1;

	pp =  (struct ckpt_task_pids *) h;

	if (args->show_task_tree) {
		for (i = 0; i < nr_tasks; i++) {
			printf("Task %d: pid %d ppid %d tgid %d"
				"pgid %d sid %d depth %d\n",
				i, pp[i].vpid, pp[i].vppid, pp[i].vtgid,
				pp[i].vpgid, pp[i].vsid, pp[i].depth);
		}
	}
	free(h);

	return 1;
}

static int image_parse_objref(struct ckpt_hdr *h, int fd, struct args *args)
{
	struct ckpt_hdr_objref *hh = (struct ckpt_hdr_objref *) h;

	VERBOSE("\t%s ref %d\n", obj_to_str(hh->objtype), hh->objref);
	return 1;
}

static int image_parse_file(struct ckpt_hdr *h, int fd, struct args *args)
{
	struct ckpt_hdr_file *hh = (struct ckpt_hdr_file *) h;

	VERBOSE("\t%s\n", file_to_str(hh->f_type));
	return 1;
}

static int image_parse_vma(struct ckpt_hdr *h, int fd, struct args *args)
{
	struct ckpt_hdr_vma *hh = (struct ckpt_hdr_vma *) h;

	VERBOSE("\t%s vmaref %d inoref %d\n", vma_to_str(hh->vma_type),
		hh->vma_objref, hh->ino_objref);
	return 1;
}

#ifdef __i386__
static int image_parse_cpu_X86(struct ckpt_hdr *h, int fd, struct args *args)
{
	struct ckpt_hdr_cpu *hh = (struct ckpt_hdr_cpu *) h;

	if (!args->show_arch_regs && !args->verbose)
		return 1;
	VERBOSE("\tax=0x%08lx bx=0x%08lx cx=0x%08lx dx=0x%08lx"
		" si=0x%08lx di=0x%08lx\n",
		(unsigned long) hh->ax, (unsigned long) hh->bx,
		(unsigned long) hh->cx, (unsigned long) hh->dx,
		(unsigned long) hh->si, (unsigned long) hh->di);
	VERBOSE("\tip=0x%08lx bp=0x%08lx sp=0x%08lx"
		" fs=0x%08lx(0x%04hx) gs=0x%08lx(0x%04hx)\n",
		(unsigned long) hh->ip, (unsigned long) hh->bp,
		(unsigned long) hh->sp, (unsigned long) hh->fs,
		(unsigned short) hh->fsindex, (unsigned long) hh->gs,
		(unsigned short) hh->gsindex);
	VERBOSE("\torig_ax=0x%08lx flags=0x%08lx"
		" cs=0x%04hx ds=0x%04hx es=0x%04hx ss=0x%04hx\n",
		(unsigned long) hh->orig_ax, (unsigned long) hh->flags,
		(unsigned short) hh->cs, (unsigned short) hh->ds,
		(unsigned short) hh->es, (unsigned short) hh->ss);

	return 1;
}
#endif

#if defined(__s390__) || defined(__s390x__)
static int image_parse_cpu_s390(struct ckpt_hdr *h, int fd, struct args *args)
{
	struct ckpt_hdr_cpu *hh = (struct ckpt_hdr_cpu *) h;
	int i;

	if (!args->show_arch_regs && !args->verbose)
		return 1;

	VERBOSE("\targs=%#lx orig_gpr2=%#lx svcnr=%d ilc=%d\n",
		(unsigned long) hh->args[0], (unsigned long) hh->orig_gpr2,
		(int) hh->svcnr, (int) hh->ilc);
	VERBOSE("\tGPRS:");
	for (i = 0; i < NUM_GPRS; i++) {
		if (!(i % 4))
			VERBOSE("\n\t");
		VERBOSE("[%d]=%#lx", i, hh->gprs[i]);
	}
	VERBOSE("\n");

	return 1;
}
#endif

#ifndef __HAVE_image_parse_cpu
/* fallback version - when no architecture support */
static int image_parse_cpu(struct ckpt_hdr *h, int fd, struct args *args)
{
	return 1;
}
#endif

static int image_parse_error(struct ckpt_hdr *h, int fd, struct args *args)
{
	struct ckpt_hdr *p;
	char *str;
	int len;

	if (!args->error && !args->verbose)
		return 1;

	if (h->len != sizeof(*h)) {
		fprintf(stderr, "invalid CKPT_HDR_ERROR header length");
		return -1;
	}

	len = image_read_obj(fd, &p);
	if (len == 0)
		fprintf(stderr, "error object: unexpected end of file");
	if (len <= 0)
		return -1;

	if (p->type != CKPT_HDR_STRING) {
		fprintf(stderr, "unexpected header type %d\n", p->type);
		free(p);
		return -1;
	}

	if (p->len - sizeof(*p) < 2) {
		fprintf(stderr, "invalid CKPT_HDR_STRING header length");
		free(p);
		return -1;
	}

	str = (char *) (p + 1);
	printf("CKPT_HDR_ERROR: %s\n", &str[1]);

	free(p);
	return (args->error ? 0 : 1);
}
