/*
 *  clone_ppc64_.S: ppc64 support for eclone()
 *
 *  Author:	Nathan Lynch <ntl@pobox.com>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <asm/unistd.h>
#include "powerpc_asm.h"

#ifndef __powerpc64__
#error This code is 64-bit only!
#endif

#ifndef __NR_eclone
#define __NR_eclone     323
#endif

/* int [r3] eclone(int (*fn)(void *arg) [r3],
 *                          int flags [r4],
 *                          void *fn_arg [r5],
 *                          struct clone_args *args [r6],
 *                          size_t args_size [r7],
 *                          pid_t *pids [r8]);
 * Creates a child task with the pids specified by pids.
 * Returns to parent only, child execution and exit is handled here.
 * On error, returns negated errno.  On success, returns the pid of the child
 * created.
 */

.text
	.global __eclone
	.section	".opd","aw"
	.align 3
__eclone:
	.quad .__eclone,.TOC.@tocbase,0
	.previous
	.global .__eclone
.__eclone:
	/* Set up parent's stack frame. */
	stdu	r1,-80(r1)

	/* Save non-volatiles */
	std	r30,64(r1)
	std	r31,72(r1)

	/* Save fn and fn_arg across system call */
	mr	r30,r3
	mr	r31,r5

	/* Set up arguments for system call. */
	mr	r3,r4	/* flags */
	mr	r4,r6	/* clone_args */
	mr	r5,r7	/* clone_args' size */
	mr	r6,r8	/* pids */

	/* Do the system call */
	li	r0,__NR_eclone
	sc

	/* Parent or child? */
	cmpdi	cr1,r3,0
	crandc	4*cr1+eq,4*cr1+eq,4*cr0+so
	bne	cr1,eclone_parent

	/* Child.  Call fn. */
	std 	r2,40(r1)	/* save TOC base */
	ld	r0,0(r30)	/* extract fn pointer from descriptor */
	ld	r2,8(r30)	/* extract TOC base from descriptor */
	mtctr	r0
	mr	r3,r31		/* fn argument */
	bctrl
	ld	r2,40(r1)	/* restore TOC base */

	/* Assume result of fn in r3 and exit. */
	li	r0,__NR_exit
	sc

eclone_parent:
	/* Restore non-volatiles. */
	ld	r31,72(r1)
	ld	r30,64(r1)

	addi	r1,r1,80

	/* Return to caller on success. */
	bnslr

	/* Handle error.  Negate the return value to signal an error
	 * to the caller, which must set errno.
	 */
	neg	r3,r3
	blr
