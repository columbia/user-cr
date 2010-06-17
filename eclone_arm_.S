/*
 *  eclone_arm_.S: ARM support for eclone()
 *
 *  Author:	Christoffer Dall <christofferdall@christofferdall.dk>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#define _ERRNO_H	1
#include <bits/errno.h>
#include <asm/unistd.h>


#define CLONE_VM      0x00000100
#define CLONE_THREAD  0x00010000

#ifndef __NR_eclone
#define __NR_eclone 366
#endif

/*
 * Implements the following system call wrapper:
 *
 *	extern int __eclone(int clone_flags_low,
 *			    struct clone_args *clone_args,
 *			    pid_t *pids);
 *
 * The system call wrapper and the system call themselves have slightly
 * different layouts and the following transformation takes place in
 * the code below:
 *
 */

        .text
	.align 4
	.globl __eclone
	.type __eclone,%function
__eclone:
	@ save flags
	mov	ip, r0

	@ do the system call
#ifdef __ARM_EABI__
	str	r7, [sp, #-4]!
	ldr	r7, =__NR_eclone
	swi	0x0
#else
	swi	__NR_eclone
#endif
	cmp	r0, #0
	beq	1f
#ifdef __ARM_EABI__
	ldr	r7, [sp], #4
#endif
	@ return to caller
	bx	lr

1:
	tst	ip, #CLONE_THREAD
	bne	3f
	mov	r0, #0xffff0fff
	mov	lr, pc
	sub	pc, r0, #31
	mov	r1, r0
	tst	ip, #CLONE_VM
	movne	r0, #-1
#ifdef __ARM_EABI__
	ldr	r7, =__NR_getpid
	swieq	0x0
#else
	swieq	__NR_getpid
#endif
	str	r0, [r1, #-1108]
	str	r0, [r1, #-1112]
3:
	@ pick the function arg and call address off the stack and execute
	ldr	r0, [sp, #4]
	mov	lr, pc
	ldr 	pc, [sp], #8

	@ and we are done, passing the return value through r0
	@b       PLTJMP(HIDDEN_JUMPTARGET(_exit))
	b	_exit

