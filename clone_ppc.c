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
