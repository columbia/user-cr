/*
 *  clone_ppc.c: support for clone_with_pid() on powerpc (32 bit)
 *
 *  Author:	Nathan Lynch <ntl@pobox.com>
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

struct target_pid_set;

extern int __clone_with_pids(int (*fn)(void *arg),
			     void *child_stack ,
			     int flags,
			     void *arg,
			     void *parent_tid,
			     void *tls,
			     void *child_tid,
			     struct target_pid_set *setp);

/*
 * libc doesn't support clone_with_pid() yet...
 * below is arch-dependent code to use the syscall
 */
#include <linux/checkpoint.h>
#if defined(__NR_clone_with_pids)

/* (see: http://lkml.indiana.edu/hypermail/linux/kernel/9604.3/0204.html) */

int clone_with_pids(int (*fn)(void *), void *child_stack, int flags,
			   struct target_pid_set *target_pids, void *arg)
{
	void *parent_tid = NULL;
	void *tls = NULL;
	void *child_tid = NULL;
	pid_t newpid;

	newpid = __clone_with_pids(fn, child_stack, flags, arg, parent_tid,
				   tls, child_tid, target_pids);

	if (newpid < 0) {
		errno = -newpid;
		return -1;
	}

	return newpid;
}

#endif

#include "eclone.h"

extern int __eclone(int (*fn)(void *arg),
		    void *child_sp,
		    int flags,
		    void *fn_arg,
		    struct clone_args *args,
		    size_t args_size,
		    pid_t *pids);

int eclone(int (*fn)(void *), void *fn_arg, int clone_flags_low,
	   struct clone_args *clone_args, pid_t *pids)
{
	struct clone_args my_args;
	unsigned long child_sp;
	int newpid;

	if (clone_args->child_stack)
		child_sp = clone_args->child_stack +
			clone_args->child_stack_size - 1;
	else
		child_sp = 0;

	my_args = *clone_args;
	my_args.child_stack = child_sp;
	my_args.child_stack_size = 0;

	newpid = __eclone(fn,
			  (void *)child_sp,
			  clone_flags_low,
			  fn_arg,
			  &my_args,
			  sizeof(my_args),
			  pids);

	if (newpid < 0) {
		errno = -newpid;
		newpid = -1;
	}

	return newpid;
}
