/*
 *  clone_x86_32.c: support for clone_with_pid() on x86_32
 *
 *  Copyright (C) Oren Laadan <orenl@cs.columbia.edu>
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
 * libc doesn't support clone_with_pid() yet...
 * below is arch-dependent code to use the syscall
 */
#include <linux/checkpoint.h>
#if defined(__NR_clone_with_pids)

/* this really belongs to some kernel header ! */
struct pid_set {
	int num_pids;
	pid_t *pids;
};

/* (see: http://lkml.indiana.edu/hypermail/linux/kernel/9604.3/0204.html) */
int clone_with_pids(int (*fn)(void *), void *child_stack, int flags,
		    struct pid_set *target_pids, void *arg)
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

#endif

#include "eclone.h"

#ifndef __NR_eclone
#define __NR_eclone 337
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

	__asm__ __volatile__(
		"int $0x80\n\t"	       /* Linux/i386 system call */
		"testl %0,%0\n\t"      /* check return value */
		"jne 1f\n\t"	       /* jump if parent */
		"popl %%ebx\n\t"       /* get subthread function */
		"call *%%ebx\n\t"      /* start subthread function */
		"movl %2,%0\n\t"
		"int $0x80\n"	       /* exit system call: exit subthread */
		"1:\n\t"
		:"=a" (retval)
		:"0" (__NR_eclone), "i" (__NR_exit),
		 "b" (clone_flags_low),	/* flags -> 1st (ebx) */
		 "c" (&my_args),	/* clone_args -> 2nd (ecx) */
		 "d" (sizeof(my_args)),	/* args_size -> 3rd (edx) */
		 "D" (pids)		/* pids -> 4th (edi) */
		);

	if (retval < 0) {
		errno = -retval;
		retval = -1;
	}
	return retval;
}
