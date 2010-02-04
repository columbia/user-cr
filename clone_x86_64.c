/*
 *  clone_x86_64.c: support for eclone() on x86_64
 *
 *  Copyright (C) Oren Laadan <orenl@cs.columbia.edu>
 *  Copyright (C) Dave Hansen <daveh@linux.vnet.ibm.com>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <asm/unistd.h>

/*
 * libc doesn't support eclone() yet...
 * below is arch-dependent code to use the syscall
 */
#include <linux/checkpoint.h>

#include "eclone.h"

#ifndef __NR_eclone
#define __NR_eclone 300
#endif

int eclone(int (*fn)(void *), void *fn_arg, int clone_flags_low,
	   struct clone_args *clone_args, pid_t *pids)
{
	struct clone_args my_args;
	long retval;
	void **newstack;

	if (clone_args->child_stack) {
		/*
		 * Set up the stack for child:
		 *  - fn_arg will be the argument for the child function
		 *  - the fn pointer will be loaded into ebx after the clone
		 */
		newstack = (void **)(unsigned long)(clone_args->child_stack +
					    clone_args->child_stack_size);
		*--newstack = fn_arg;
		*--newstack = fn;
	} else
		newstack = (void **)0;

	my_args = *clone_args;
	my_args.child_stack = (unsigned long)newstack;
	my_args.child_stack_size = 0;

        __asm__  __volatile__(
		"movq %6, %%r10\n\t"	/* pids in r10*/
		"syscall\n\t"		/* Linux/x86_64 system call */
		"testq %0,%0\n\t"	/* check return value */
		"jne 1f\n\t"		/* jump if parent */
		"popq %%rax\n\t"	/* get subthread function */
		"popq %%rdi\n\t"	/* get the subthread function arg */
		"call *%%rax\n\t"	/* start subthread function */
		"movq %2,%0\n\t"
		"syscall\n"		/* exit system call: exit subthread */
		"1:\n\t"
		:"=a" (retval)
		:"0" (__NR_eclone), "i" (__NR_exit),
		 "D" (clone_flags_low),	/* rdi */
		 "S" (&my_args),	/* rsi */
		 "d" (sizeof(my_args)),	/* rdx */
		 "m" (pids)		/* gets moved to r10 */
		:"rcx", "r10", "r11", "cc"
		);
				        /*
         * glibc lists 'cc' as clobbered, so we might as
	 * well do it too.  'r11' and 'rcx' are clobbered
	 * by the 'syscall' instruction itself.  'r8' and
	 * 'r9' are clobbered by the clone, but that
	 * thread will exit before getting back out to C.
         */

	if (retval < 0) {
		errno = -retval;
		retval = -1;
	}
	return retval;
}
