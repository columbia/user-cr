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
