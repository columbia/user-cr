/*
 *  clone_s390.c: support for clone_with_pid() on s390x (64 bit)
 *
 *  Copyright (C) IBM Corporation
 *
 *  Author:	Serge Hallyn <serue@us.ibm.com>
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

#define do_clone_with_pids(stack, flags, ptid, ctid, setp) ({ \
	register unsigned long int __r2 asm ("2") = (unsigned long int)(stack);\
	register unsigned long int __r3 asm ("3") = (unsigned long int)(flags);\
	register unsigned long int __r4 asm ("4") = (unsigned long int)(ptid); \
	register unsigned long int __r5 asm ("5") = (unsigned long int)(ctid); \
	register unsigned long int __r6 asm ("6") = (unsigned long int)(NULL); \
	register unsigned long int __r7 asm ("7") = (unsigned long int)(setp); \
	register unsigned long int __result asm ("2"); \
	__asm__ __volatile__( \
		" lghi %%r1,%7\n" \
		" svc 0\n" \
		: "=d" (__result) \
		: "0" (__r2), "d" (__r3), \
		  "d" (__r4), "d" (__r5), "d" (__r6), "d" (__r7), \
		  "i" (__NR_clone_with_pids) \
		: "1", "cc", "memory" \
	); \
		__result; \
	})

int clone_with_pids(int (*fn)(void *), void *child_stack, int flags,
			struct pid_set *target_pids, void *arg)
{
	long retval;
	retval = do_clone_with_pids(child_stack, flags, NULL, NULL,
				    target_pids);

	if (retval < 0) {
		errno = -retval;
		return -1;
	} else if (retval == 0) {
		return fn(arg);
	} else
		return retval;
}

#endif  /* !defined(__NR_clone_with_pids) */

#include "eclone.h"

#ifndef __NR_eclone
#define __NR_eclone 332
#endif

typedef unsigned long long u64;

#define do_eclone(flags, pids, args, sz) \
( { \
  register unsigned long int __r1 asm ("1") = (unsigned long int)(__NR_eclone); \
  register unsigned long int __r2 asm ("2") = (unsigned long int)(flags); \
  register unsigned long int __r3 asm ("3") = (unsigned long int)(args); \
  register unsigned long int __r4 asm ("4") = (unsigned long int)(sz); \
  register unsigned long int __r5 asm ("5") = (unsigned long int)(pids); \
  register long int __result asm ("2"); \
  __asm__ __volatile__( \
	  " svc 0\n" /* do __NR_eclone syscall */ \
	  " ltgr %%r2,%%r2\n" /* returned 0? */ \
	  " jnz 1f\n" /* if not goto label 1 */ \
	  " lg %%r3,0(%%r15)\n"	  /* get fnarg off stack into arg 1 */ \
	  " lg %%r2,8(%%r15)\n"	  /* get fn off stack int r3 basr*/ \
	  " lgr %%r1,%%r15\n" /* tmp store old stack pointer */ \
	  " aghi %%r15,-160\n" /* move the stack */ \
	  " stg %%r1,0(%%r15)\n" /* and save old stack pointer */ \
	  " basr %%r14,%%r3\n" /* call fn(arg) */ \
	  " svc 1\n"  /* call exit */ \
	  " 1:\n" \
	  : "=d" (__result) \
	  : "d" (__r1), "0" (__r2), "d" (__r3), "d" (__r4), "d" (__r5) \
	  : "memory"); \
	__result; \
} )

int eclone(int (*fn)(void *), void *fn_arg, int clone_flags_low,
	   struct clone_args *clone_args, pid_t *pids)
{
	struct clone_args my_args;
	u64 *child_sp;
	int rc;

	if (clone_args->child_stack) {
		child_sp = (void *)(clone_args->child_stack +
				    clone_args->child_stack_size);
		*--child_sp = (u64)fn_arg;
		*--child_sp = (u64)fn;
	} else
		child_sp = (u64 *)0;

	my_args = *clone_args;
	my_args.child_stack = (unsigned long)child_sp;
	my_args.child_stack_size = 0;

	rc = do_eclone(clone_flags_low, pids, &my_args,
		       sizeof(struct clone_args));
	if (rc < 0) {
		errno = -rc;
		rc = -1;
	}

	return rc;
}
