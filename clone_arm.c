/*
 *  clone_arm.c: support for eclone() on ARM
 *
 *  Author:	Christoffer Dall <christofferdall@christofferdall.dk>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <asm/unistd.h>

/*
 * libc doesn't support eclone() yet...
 * below is arch-dependent code to use the syscall
 */
#include <linux/checkpoint.h>

#include "eclone.h"

extern int __eclone(int clone_flags_low,
		    struct clone_args *clone_args,
		    unsigned int args_size,
		    pid_t *pids);

static unsigned long get_stack_pointer(unsigned long base, unsigned long size)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	return (base + size - page_size) - 1;
}

int eclone(int (*fn)(void *), void *fn_arg, int clone_flags_low,
	   struct clone_args *clone_args, pid_t *pids)
{
	struct clone_args my_args;
	long newpid;
	void **sp = NULL;

	if (!fn) {
		fprintf(stderr, "Please provide a valid function pointer "
				"for the child process.\n");
		return -1;
	}

	if (clone_args->child_stack) {
		sp = (void **)get_stack_pointer(clone_args->child_stack,
						clone_args->child_stack_size);
		*--sp = fn_arg;
		*--sp = fn;
	} else {
		fprintf(stderr, "The ARM architecture requires a valid child "
				"stack. clon_args->child_stack was 0.\n");
		return -1;
	}


	my_args = *clone_args;
	my_args.child_stack = (unsigned long long)sp;
	my_args.child_stack_size = 0;

	newpid = __eclone(clone_flags_low,
			  &my_args,
			  sizeof(my_args),
			  pids);

	if (newpid < 0) {
		errno = -newpid;
		newpid = -1;
	}

	return newpid;
}
