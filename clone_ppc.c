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

#include "eclone.h"

extern int __eclone(int (*fn)(void *arg),
		    int flags,
		    void *fn_arg,
		    struct clone_args *args,
		    size_t args_size,
		    pid_t *pids);

#ifdef __powerpc64__
#define MIN_STACK_FRAME 48
#else
#define MIN_STACK_FRAME 16
#endif

static unsigned long stack_setup_frame(unsigned long base, unsigned long size)
{
	unsigned long *sp;

	sp =  (unsigned long *)(((base + size - 1) & ~0xf) - MIN_STACK_FRAME);
	*sp = 0;

	return (unsigned long)sp;
}

int eclone(int (*fn)(void *), void *fn_arg, int clone_flags_low,
	   struct clone_args *clone_args, pid_t *pids)
{
	struct clone_args my_args;
	unsigned long child_sp;
	int newpid;

	if (clone_args->child_stack)
		child_sp = stack_setup_frame(clone_args->child_stack,
					     clone_args->child_stack_size);
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
