/*
 * Copyright 2008,2009 IBM Corp.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>

#include "clone.h"
#include "eclone.h"
#include "genstack.h"
#include "compat.h"

extern pid_t getpgid(pid_t pid);
extern pid_t getsid(pid_t pid);

static const char* procname;

int  __attribute__((weak)) unshare(int flags)
{
	return syscall(__NR_unshare, flags);
}

static void usage(const char *name)
{
	printf("usage: %s [-h] [-c] [-mnuUip] [-P <pid-file>]"
			"[command [arg ..]]\n", name);
	printf("\n");
	printf("  -h		this message\n");
	printf("\n");
	printf("  -z <pid>	use eclone and specify chosen pid\n");
	printf("  		Note that -z and -p are not compatible\n");
	printf("  -c		use 'clone' rather than 'unshare' system call\n");
	printf("  -g		launch in new cgroup\n");
	printf("  -m		mount namespace\n");
	printf("  -n		network namespace\n");
	printf("  -u		utsname namespace\n");
	printf("  -U		userid namespace\n");
	printf("  -i		ipc namespace\n");
	printf("  -P <pid-file>	File in which to write global pid of cinit\n");
	printf("  -p		pid namespace\n");
	printf("  -t		mount new devpts\n");
	printf("  -f <flag>	extra clone flags\n");
	printf("\n");
	printf("(C) Copyright IBM Corp. 2006\n");
	printf("\n");
	exit(1);
}

static int string_to_ul(const char *str, unsigned long int *res)
{
	char *tail;
	long long int r;

	if (!*str)
		return -1;

	errno = 0;

	r = strtol(str, &tail, 16);

	/*
	 * according to strtol(3), if errno is set or tail does no point
	 * to the ending '\0', the conversion failed.
	 */
	if (errno || *tail)
		return -1;

	*res = r;
	return 0;
}

/*
 * Copied following opentty() from Fedora's util-linux rpm
 * I just changed the "FATAL" message below from syslog()
 * to printf
 */
static void
opentty(const char * tty) {
        int i, fd, flags;

        fd = open(tty, O_RDWR | O_NONBLOCK);
        if (fd == -1) {
		printf("FATAL: can't reopen tty: %s", strerror(errno));
                sleep(1);
                exit(1);
        }

        flags = fcntl(fd, F_GETFL);
        flags &= ~O_NONBLOCK;
        fcntl(fd, F_SETFL, flags);

        for (i = 0; i < fd; i++)
                close(i);
        for (i = 0; i < 3; i++)
                if (fd != i)
                        dup2(fd, i);
        if (fd >= 3)
                close(fd);
}
// Code copy end

int do_newcgrp = 0;

int load_cgroup_dir(char *dest, int len)
{
	FILE *f = fopen("/proc/mounts", "r");
	char buf[200];
	char *name, *path, *fsname, *options, *p1, *p2, *s;
	if (!f)
		return 0;
	while (fgets(buf, 200, f)) {
		name = strtok_r(buf, " ", &p1);
		path = strtok_r(NULL, " ", &p1);
		fsname = strtok_r(NULL, " ", &p1);
		options = strtok_r(NULL, " ", &p1);
		if (strcmp(fsname, "cgroup") != 0)
			continue;

		/* make sure the freezer is composed */
		s = strtok_r(options, ",", &p2);
		while (s && strcmp(s, "freezer") != 0)
			s = strtok_r(NULL, ",", &p2);
		if (!s)
			continue;
		strncpy(dest, path, len);
		fclose(f);
		return 1;
	}
	fclose(f);
	printf("Freezer not mounted\n");
	return 0;
}

int move_to_new_cgroup(int newcgroup)
{
	char cgroupname[150], cgroupbase[100], tasksfname[200];
	FILE *fout;
	int ret;

	if (!load_cgroup_dir(cgroupbase, 100))
		return 0;

	snprintf(cgroupname, 150, "%s/%d", cgroupbase, newcgroup);
	ret = mkdir(cgroupname, 0755);
	if (ret && errno != EEXIST)
		return 0;
	snprintf(tasksfname, 200, "%s/tasks", cgroupname);
	fout = fopen(tasksfname, "w");
	if (!fout)
		return 0;
	fprintf(fout, "%ld\n", syscall(__NR_getpid));
	fclose(fout);
	return 1;
}

int pipefd[2];

/* gah. opentty will close the pipefd */
int check_newcgrp(void)
{
	int ret, newgroup;
	char buf[20];

	if (!do_newcgrp)
		return 0;

	close(pipefd[1]);
	ret = read(pipefd[0], buf, 20);
	close(pipefd[0]);
	if (ret == -1) {
		perror("read");
		return 1;
	}
	newgroup = atoi(buf);
	if (!move_to_new_cgroup(newgroup))
		return 1;
	do_newcgrp = 0;
	return 0;
}

int do_child(void *vargv)
{
	char **argv = vargv;

	if (check_newcgrp())
		return 1;

	/* if pid == 1 then remount /proc */
	/* But if the container has no /proc don't fret */
	if (syscall(__NR_getpid) == 1) {
		umount2("/proc", MNT_DETACH);
		mount("proc", "/proc", "proc", 0, NULL);
	}

	/* check if we should remount devpts */
	if (strcmp(argv[0], "newpts") == 0) {
		struct stat ptystat;
		argv++;
		if (lstat("/dev/ptmx", &ptystat) < 0) {
			perror("stat /dev/ptmx");
			return -1;
		}
		if ((ptystat.st_mode & S_IFMT) != S_IFLNK) {
			printf("Error: /dev/ptmx must be a link to /dev/pts/ptmx\n");
			printf("       do: chmod 666 /dev/pts/ptmx\n");
			printf("           rm /dev/ptmx\n");
			printf("           ln -s /dev/pts/ptmx /dev/ptmx\n");
			return -1;
		}

		/* if container had no /dev/pts mounted don't fret */
		umount2("/dev/pts", MNT_DETACH);

		if (mount("pts", "/dev/pts", "devpts", 0, "ptmxmode=666,newinstance") < 0) {
			perror("mount -t devpts -o newinstance");
			return -1;
		}
	}

	execve(argv[0], argv, __environ);
	perror("execve");
	return 1;
}

void write_pid(char *pid_file, int pid)
{
	FILE *fp;

	if (!pid_file)
		return;

	fp = fopen(pid_file, "w");
	if (!fp) {
		perror("fopen, pid_file");
		exit(1);
	}
	fprintf(fp, "%d", pid);
	fflush(fp);
	fclose(fp);
}

int main(int argc, char *argv[])
{
	int c;
	unsigned long flags = 0, eflags = 0;
	char ttyname[256];
	int status;
	int ret, use_clone = 0, newpts = 0;
	int pid;
	char *pid_file = NULL;
	size_t nr_pids = 1;
	pid_t chosen_pid = 0;
	char **newargv;

	procname = basename(argv[0]);

	memset(ttyname, '\0', sizeof(ttyname));
	readlink("/proc/self/fd/0", ttyname, sizeof(ttyname));

	while ((c = getopt(argc, argv, "+mguUiphz:cntf:P:")) != EOF) {
		switch (c) {
		case 'g': do_newcgrp = getpid();		break;
		case 'm': flags |= CLONE_NEWNS;			break;
		case 'c': use_clone = 1;			break;
		case 'P': pid_file = optarg; 			break;
		case 'u': flags |= CLONE_NEWUTS;		break;
		case 'i': flags |= CLONE_NEWIPC;		break;
		case 'U': flags |= CLONE_NEWUSER;		break;
		case 'n': flags |= CLONE_NEWNET;		break;
		case 'p': flags |= CLONE_NEWNS|CLONE_NEWPID;	break;
		case 't': newpts = 1; flags |= CLONE_NEWNS;	break;
		case 'z': chosen_pid = atoi(optarg);		break;
		case 'f': if (!string_to_ul(optarg, &eflags)) {
				flags |= eflags;
				break;
			}
		case 'h':
		default:
			usage(procname);
		}
	};

	if (chosen_pid) {
		use_clone = 1;
		if (flags & CLONE_NEWPID) {
			printf("Error: can't use CLONE_NEWPID and pick a pid\n");
			exit(1);
		}
	}
	argv = &argv[optind];
	argc = argc - optind;
	if (newpts) {
		/* tell do_child about newpts through first arg */
		int i;
		newargv = (char **) malloc(sizeof(char *) * (argc+2));
		newargv[0] = "newpts";
		newargv[argc+1] = NULL;
		for (i=0; i<argc; i++)
			newargv[i+1] = argv[i];
		argv = newargv;
	}

	if (do_newcgrp) {
		ret = pipe(pipefd);
		if (ret) {
			perror("pipe");
			return -1;
		}
		do_newcgrp = pipefd[0];
	}

	if (use_clone) {
		struct clone_args clone_args;
		size_t stacksize = 4 * sysconf(_SC_PAGESIZE);
		genstack stack = genstack_alloc(stacksize);

		if (!stack) {
			perror("genstack_alloc");
			return -1;
		}

		memset(&clone_args, 0, sizeof(clone_args));
		clone_args.child_stack = (unsigned long)genstack_base(stack);
		clone_args.child_stack_size = genstack_size(stack);
		clone_args.nr_pids = nr_pids;

		printf("about to clone with %lx\n", flags);
		if (chosen_pid)
			printf("Will choose pid %d\n", chosen_pid);
		flags |= SIGCHLD;
		pid = eclone(do_child, argv, flags, &clone_args, &chosen_pid);
		if (pid == -1) {
			perror("clone");
			return -1;
		}
	} else {
		if ((pid = fork()) == 0) {
			// Child.
			//print_my_info(procname, ttyname);

			if (check_newcgrp())
				return 1;
			opentty(ttyname);

			printf("about to unshare with %lx\n", flags);
			ret = unshare(flags);
			if (ret < 0) {
				perror("unshare");
				return 1;
			}

			return do_child((void*)argv);
		}

	}
	if (pid != -1 && do_newcgrp) {
		char buf[20];
		snprintf(buf, 20, "%d", pid);
		close(pipefd[0]);
		write(pipefd[1], buf, strlen(buf)+1);
		close(pipefd[1]);
	}

	write_pid(pid_file, pid);

	if ((ret = waitpid(pid, &status, __WALL)) < 0)
		printf("waitpid() returns %d, errno %d\n", ret, errno);

	exit(0);
}
