/*
 *  clone_ppc_.S: support for clone_with_pid() on powerpc (32 bit)
 *
 *  Author:	Nathan Lynch <ntl@pobox.com>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <asm/unistd.h>
#include "powerpc_asm.h"

/* int [r3] clone_with_pids(int (*fn)(void *arg) [r3],
 *                          void *child_stack [r4],
 *                          int flags [r5],
 *                          void *arg [r6],
 *                          void *parent_tid [r7],
 *                          void *tls [r8],
 *                          void *child_tid [r9],
 *                          struct target_pid_set *setp [r10]);
 * Creates a child task with the pids specified by setp.
 * Returns to parent only, child execution and exit is handled here.
 * On error, returns negated errno.  On success, returns the pid of the child
 * created.
 */

.text
.globl __clone_with_pids
__clone_with_pids:

/* No argument validation. */

/* Set up parent's stack frame. */
stwu	r1,-32(r1)

	/* Save non-volatiles (r28-r31) which we plan to use. */
	stmw	r28,16(r1)

	/* Set up child's stack frame. */
	clrrwi	r4,r4,4
	li	r0,0
	stw	r0,-16(r4)

	/* Save fn, stack pointer, flags, and arg across system call. */
	mr	r28,r3
	mr	r29,r4
	mr	r30,r5
	mr	r31,r6

	/* Set up arguments for system call.  Stack pointer is already in r4. */
	mr	r3,r5	/* flags */
	mr	r5,r7	/* parent_tid */
	mr	r6,r8	/* tls */
	mr	r7,r9	/* child_tid */
	mr	r8,r10	/* setp */

	/* Do the system call */
	li	r0,__NR_clone_with_pids
	sc

	/* Parent or child? */
	cmpwi	cr1,r3,0
	crandc	4*cr1+eq,4*cr1+eq,4*cr0+so
	bne	cr1,parent

	/* Child. Call fn. */
	mtctr	r28
	mr 	r3,r31
	bctrl

	/* Assume result of fn in r3 and exit. */
	li	r0,__NR_exit
	sc

parent:
	/* Restore non-volatiles. */
	lmw	r28,16(r1)

	addi	r1,r1,32

	/* Return to caller on success. */
	bnslr

	/* Handle error.  Negate the return value to signal an error
	 * to the caller, which must set errno.
	 */
	neg	r3,r3
	blr

