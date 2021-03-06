/*
 * Generated by extract-headers.sh.
 */
#ifndef _LINUX_CHECKPOINT_H_
#define _LINUX_CHECKPOINT_H_

#include <unistd.h>
/*
 *  Generic checkpoint-restart
 *
 *  Copyright (C) 2008-2010 Oren Laadan
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#define CHECKPOINT_VERSION 6

/* checkpoint user flags */
#define CHECKPOINT_SUBTREE 0x1
#define CHECKPOINT_NETNS 0x2

/* restart user flags */
#define RESTART_TASKSELF 0x1
#define RESTART_FROZEN 0x2
#define RESTART_GHOST 0x4
#define RESTART_KEEP_LSM 0x8
#define RESTART_CONN_RESET 0x10

/* misc user visible */
#define CHECKPOINT_FD_NONE -1


#if __arm__

#	define __NR_OABI_SYSCALL_BASE 0x900000
#	if defined(__thumb__) || defined(__ARM_EABI__)
#		define __NR_SYSCALL_BASE	0
#	else
#		define __NR_SYSCALL_BASE	__NR_OABI_SYSCALL_BASE
#	endif


#	ifndef __NR_eclone
#		define __NR_eclone (__NR_SYSCALL_BASE+376)
#	endif

#	ifndef __NR_checkpoint
#		define __NR_checkpoint (__NR_SYSCALL_BASE+377)
#	endif

#	ifndef __NR_restart
#		define __NR_restart (__NR_SYSCALL_BASE+378)
#	endif

#elif __powerpc__

#	ifndef __NR_eclone
#		define __NR_eclone 351
#	endif

#elif __s390x__

#	ifndef __NR_eclone
#		define __NR_eclone 340
#	endif

#	ifndef __NR_checkpoint
#		define __NR_checkpoint 341
#	endif

#	ifndef __NR_restart
#		define __NR_restart 342
#	endif

#elif __i386__

#	ifndef __NR_eclone
#		define __NR_eclone 347
#	endif

#	ifndef __NR_checkpoint
#		define __NR_checkpoint 348
#	endif

#	ifndef __NR_restart
#		define __NR_restart 349
#	endif

#elif __x86_64__

#	ifndef __NR_eclone
#		define __NR_eclone 312
#	endif

#	ifndef __NR_checkpoint
#		define __NR_checkpoint 313
#	endif

#	ifndef __NR_restart
#		define __NR_restart 314
#	endif

#else

#if !defined(__NR_checkpoint) || !defined(__NR_restart)
#error "Architecture does not have definitons for __NR_(checkpoint|restart)"
#endif

#endif
#endif /* _LINUX_CHECKPOINT_H_ */
