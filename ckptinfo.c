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
"\t -v,--verbose          verbose output\n"
"";

struct args {
	int error;
	int verbose;
};

int __verbose = 0;

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
static int image_parse_error(struct ckpt_hdr *h, int fd, struct args *args);

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
		{ NULL,		0,			NULL, 0 }
	};
	static char optc[] = "hve";

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
	ssize_t nread;
	int nleft;

	for (nleft = len; nleft; nleft -= nread) {
		nread = read(fd, buf, nleft);
		if (nread < 0 && errno == -EAGAIN)
			continue;
		if (nread < 0)
			return -1;
		if (nread == 0) {
			VERBOSE("info: reached end of file\n");
			return 0;
		}
		buf += nread;
	}
	return len;
}

static int image_read_obj(int fd, struct ckpt_hdr **hh)
{
	struct ckpt_hdr h, *p = NULL;
	int ret;

	ret = __image_read(fd, &h, sizeof(h));
	if (ret < 0) {
		perror("read from image");
		return ret;
	}
	if (ret == 0)
		return 0;

	VERBOSE("info: object %s len %d\n", hdr_to_str(h.type), h.len);

	p = malloc(h.len);
	if (!p) {
		fprintf(stderr, "malloc of %d failed\n", h.len);
		return -1;
	}

	*p = h;

	ret = __image_read(fd, (p + 1), h.len - sizeof(h));
	if (ret < 0) {
		perror("read from image");
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
		case CKPT_HDR_FILE:
			ret = image_parse_file(h, fd, args);
			break;
		case CKPT_HDR_VMA:
			ret = image_parse_vma(h, fd, args);
			break;
		case CKPT_HDR_ERROR:
			ret = image_parse_error(h, fd, args);
			break;
		}
		free(h);
	} while (ret > 0);

	return ret;
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
	if (len < 0)
		return len;
	if (len == 0) {
		fprintf(stderr, "unexpected end of file");
		return -1;
	}

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
	printf("CKPT_HDR_ERROR: %s", &str[1]);

	free(p);
	return (args->error ? 0 : 1);
}
