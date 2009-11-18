#ifndef CLONE_H
#define CLONE_H
/*
 *  Copyright (C) 2007 IBM Corporation
 *
 *  Author: Cedric Le Goater <clg@fr.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 *
 */
#include <sys/syscall.h>

#ifndef HAVE_UNSHARE

#if __i386__
#    define __NR_unshare 310
#elif __x86_64__
#    define __NR_unshare 272
#elif __ia64__
#    define __NR_unshare 1296
#elif __s390x__
#    define __NR_unshare 303
#elif __powerpc__
#    define __NR_unshare 282
#else
#    error "Architecture not supported"
#endif

#endif /* HAVE_UNSHARE */

#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS		0x04000000
#endif

#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC		0x08000000
#endif

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER		0x10000000
#endif

#ifndef CLONE_NEWPID
#define CLONE_NEWPID		0x20000000
#endif

#ifndef CLONE_NEWNET
#define CLONE_NEWNET		0x40000000
#endif

#endif /* CLONE_H */
