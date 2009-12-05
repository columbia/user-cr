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

/*
 * libc doesn't support eclone() yet...
 * below is arch-dependent code to use the syscall
 */
#include <linux/checkpoint.h>

#include "eclone.h"

extern int __eclone(int (*fn)(void *arg),
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

	/* The stack pointer for the child is communicated to the
	 * kernel via clone_args.child_stack, and to the __eclone
	 * assembly wrapper via the child_sp argument [r4].  So we
	 * need to align child_sp here and ensure that the wrapper and
	 * the kernel receive the same value.
	 */
	if (clone_args->child_stack)
		child_sp = (clone_args->child_stack +
			    clone_args->child_stack_size - 1) & ~0xf;
	else
		child_sp = 0;

	my_args = *clone_args;
	my_args.child_stack = child_sp;
	my_args.child_stack_size = 0;

	newpid = __eclone(fn,
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
