/*
 *  clone_ppc_.S: ppc32 support for eclone()
 *
 *  Author:	Nathan Lynch <ntl@pobox.com>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <asm/unistd.h>
#include "powerpc_asm.h"

#ifdef __powerpc64__
#error This code is 32-bit only!
#endif

#ifndef __NR_eclone
#define __NR_eclone     323
#endif

/* int [r3] eclone(int (*fn)(void *arg) [r3],
 *                          void *child_sp [r4],
 *                          int flags [r5],
 *                          void *fn_arg [r6],
 *                          struct clone_args *args [r7],
 *                          size_t args_size [r8],
 *                          pid_t *pids [r9]);
 * Creates a child task with the pids specified by pids.
 * Returns to parent only, child execution and exit is handled here.
 * On error, returns negated errno.  On success, returns the pid of the child
 * created.
 */

.globl __eclone
__eclone:

	/* No argument validation. */

	/* Set up parent's stack frame. */
	stwu	r1,-32(r1)

	/* Save non-volatiles (r28-r31) which we plan to use. */
	stmw	r28,16(r1)

	/* Set up child's stack frame. */
	clrrwi	r4,r4,4
	li	r0,0
	stw	r0,-16(r4)

	/* Save fn, stack pointer, flags, and fn_arg across system call. */
	mr	r28,r3
	mr	r29,r4
	mr	r30,r5
	mr	r31,r6

	/* Set up arguments for system call. */
	mr	r3,r5	/* flags */
	mr	r4,r7	/* clone_args */
	mr	r5,r8	/* clone_args' size */
	mr	r6,r9	/* pids */

	/* Do the system call */
	li	r0,__NR_eclone
	sc

	/* Parent or child? */
	cmpwi	cr1,r3,0
	crandc	4*cr1+eq,4*cr1+eq,4*cr0+so
	bne	cr1,eclone_parent

	/* Child. Call fn. */
	mtctr	r28
	mr	r3,r31
	bctrl

	/* Assume result of fn in r3 and exit. */
	li	r0,__NR_exit
	sc

eclone_parent:
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
