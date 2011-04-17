/*
 * Generated by extract-headers.sh.
 */
#ifndef _CHECKPOINT_CKPT_HDR_H_
#define _CHECKPOINT_CKPT_HDR_H_

#include <unistd.h>
/*
 *  Generic container checkpoint-restart
 *
 *  Copyright (C) 2008-2010 Oren Laadan
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of the Linux
 *  distribution for more details.
 */

#include <sys/types.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/un.h>
#include <netinet/in.h>

/*
 * /usr/include/linux/security.h is not exported to userspace, so
 * we need this value here for userspace restart.c to read.
 *
 * CHECKPOINT_LSM_NAME_MAX should be SECURITY_NAME_MAX
 * security_may_restart() has a BUILD_BUG_ON to enforce that.
 */
#define CHECKPOINT_LSM_NAME_MAX 10

/*
 * Macros to help generate a build break if an ambiguous type changes
 * in such a way that the size differs from the unambiguous type we
 * actually write to the checkpoint stream.
 *
 * Examples:
 *
 * CKPT_BUILD_BUG_ON_MISMATCH(short, __u16);
 * CKPT_BUILD_BUG_ON_MISMATCH(CKPT_STRUCT_MEMBER(mystruct, mymember),
 *                            CKPT_STRUCT_MEMBER(ckpt_hdr_foo, bar));
 *
 */
#define CKPT_STRUCT_MEMBER(type,member) (((struct type *)(NULL))->member)
#define CKPT_BUILD_BUG_ON_MISMATCH(a,b) (BUILD_BUG_ON(sizeof(a) != sizeof(b)))

/*
 * To maintain compatibility between 32-bit and 64-bit architecture flavors,
 * keep data 64-bit aligned: use padding for structure members, and use
 * __attribute__((aligned (8))) for the entire structure.
 *
 * Quoting Arnd Bergmann:
 *   "This structure has an odd multiple of 32-bit members, which means
 *   that if you put it into a larger structure that also contains 64-bit
 *   members, the larger structure may get different alignment on x86-32
 *   and x86-64, which you might want to avoid. I can't tell if this is
 *   an actual problem here. ... In this case, I'm pretty sure that
 *   sizeof(ckpt_hdr_task) on x86-32 is different from x86-64, since it
 *   will be 32-bit aligned on x86-32."
 */

/*
 * header format: 'struct ckpt_hdr' must prefix all other headers. Therfore
 * when a header is passed around, the information about it (type, size)
 * is readily available. Structs that include a struct ckpt_hdr are named
 * struct ckpt_hdr_* by convention (usualy the struct ckpt_hdr is the first
 * member).
 */
struct ckpt_hdr {
	__u32 type;
	__u32 len;
} __attribute__((aligned(8)));

#include <asm/termbits.h>
#include <asm/checkpoint_hdr.h>

/* header types */
enum {
	CKPT_HDR_HEADER = 1,
#define CKPT_HDR_HEADER CKPT_HDR_HEADER
	CKPT_HDR_HEADER_ARCH,
#define CKPT_HDR_HEADER_ARCH CKPT_HDR_HEADER_ARCH
	CKPT_HDR_CONTAINER,
#define CKPT_HDR_CONTAINER CKPT_HDR_CONTAINER
	CKPT_HDR_BUFFER,
#define CKPT_HDR_BUFFER CKPT_HDR_BUFFER
	CKPT_HDR_STRING,
#define CKPT_HDR_STRING CKPT_HDR_STRING
	CKPT_HDR_OBJREF,
#define CKPT_HDR_OBJREF CKPT_HDR_OBJREF
	CKPT_HDR_LSM_INFO,
#define CKPT_HDR_LSM_INFO CKPT_HDR_LSM_INFO
	CKPT_HDR_SECURITY,
#define CKPT_HDR_SECURITY CKPT_HDR_SECURITY

	CKPT_HDR_PIDS = 101,
#define CKPT_HDR_PIDS CKPT_HDR_PIDS
	CKPT_HDR_TREE,
#define CKPT_HDR_TREE CKPT_HDR_TREE
	CKPT_HDR_TASK,
#define CKPT_HDR_TASK CKPT_HDR_TASK
	CKPT_HDR_TASK_NS,
#define CKPT_HDR_TASK_NS CKPT_HDR_TASK_NS
	CKPT_HDR_TASK_OBJS,
#define CKPT_HDR_TASK_OBJS CKPT_HDR_TASK_OBJS
	CKPT_HDR_RESTART_BLOCK,
#define CKPT_HDR_RESTART_BLOCK CKPT_HDR_RESTART_BLOCK
	CKPT_HDR_THREAD,
#define CKPT_HDR_THREAD CKPT_HDR_THREAD
	CKPT_HDR_CPU,
#define CKPT_HDR_CPU CKPT_HDR_CPU
	CKPT_HDR_NS,
#define CKPT_HDR_NS CKPT_HDR_NS
	CKPT_HDR_UTS_NS,
#define CKPT_HDR_UTS_NS CKPT_HDR_UTS_NS
	CKPT_HDR_IPC_NS,
#define CKPT_HDR_IPC_NS CKPT_HDR_IPC_NS
	CKPT_HDR_MNT_NS,
#define CKPT_HDR_MNT_NS CKPT_HDR_MNT_NS
	CKPT_HDR_CAPABILITIES,
#define CKPT_HDR_CAPABILITIES CKPT_HDR_CAPABILITIES
	CKPT_HDR_USER_NS,
#define CKPT_HDR_USER_NS CKPT_HDR_USER_NS
	CKPT_HDR_CRED,
#define CKPT_HDR_CRED CKPT_HDR_CRED
	CKPT_HDR_USER,
#define CKPT_HDR_USER CKPT_HDR_USER
	CKPT_HDR_GROUPINFO,
#define CKPT_HDR_GROUPINFO CKPT_HDR_GROUPINFO
	CKPT_HDR_TASK_CREDS,
#define CKPT_HDR_TASK_CREDS CKPT_HDR_TASK_CREDS

	/* 201-299: reserved for arch-dependent */

	CKPT_HDR_FILE_TABLE = 301,
#define CKPT_HDR_FILE_TABLE CKPT_HDR_FILE_TABLE
	CKPT_HDR_FILE_DESC,
#define CKPT_HDR_FILE_DESC CKPT_HDR_FILE_DESC
	CKPT_HDR_FILE_NAME,
#define CKPT_HDR_FILE_NAME CKPT_HDR_FILE_NAME
	CKPT_HDR_FILE,
#define CKPT_HDR_FILE CKPT_HDR_FILE
	CKPT_HDR_PIPE_BUF,
#define CKPT_HDR_PIPE_BUF CKPT_HDR_PIPE_BUF
	CKPT_HDR_TTY,
#define CKPT_HDR_TTY CKPT_HDR_TTY
	CKPT_HDR_TTY_LDISC,
#define CKPT_HDR_TTY_LDISC CKPT_HDR_TTY_LDISC
	CKPT_HDR_EPOLL_ITEMS,  /* must be after file-table */
#define CKPT_HDR_EPOLL_ITEMS CKPT_HDR_EPOLL_ITEMS

	CKPT_HDR_MM = 401,
#define CKPT_HDR_MM CKPT_HDR_MM
	CKPT_HDR_VMA,
#define CKPT_HDR_VMA CKPT_HDR_VMA
	CKPT_HDR_PGARR,
#define CKPT_HDR_PGARR CKPT_HDR_PGARR
	CKPT_HDR_HPAGE,
#define CKPT_HDR_HPAGE CKPT_HDR_HPAGE
	CKPT_HDR_MM_CONTEXT,
#define CKPT_HDR_MM_CONTEXT CKPT_HDR_MM_CONTEXT

	CKPT_HDR_FS = 451,  /* must be after file-table, mm */
#define CKPT_HDR_FS CKPT_HDR_FS

	CKPT_HDR_IPC = 501,
#define CKPT_HDR_IPC CKPT_HDR_IPC
	CKPT_HDR_IPC_SHM,
#define CKPT_HDR_IPC_SHM CKPT_HDR_IPC_SHM
	CKPT_HDR_IPC_MSG,
#define CKPT_HDR_IPC_MSG CKPT_HDR_IPC_MSG
	CKPT_HDR_IPC_MSG_MSG,
#define CKPT_HDR_IPC_MSG_MSG CKPT_HDR_IPC_MSG_MSG
	CKPT_HDR_IPC_SEM,
#define CKPT_HDR_IPC_SEM CKPT_HDR_IPC_SEM
	CKPT_HDR_TASK_SEM_UNDO_LIST,
#define CKPT_HDR_TASK_SEM_UNDO_LIST CKPT_HDR_TASK_SEM_UNDO_LIST
	CKPT_HDR_TASK_SEM_UNDO,
#define CKPT_HDR_TASK_SEM_UNDO CKPT_HDR_TASK_SEM_UNDO

	CKPT_HDR_SIGHAND = 601,
#define CKPT_HDR_SIGHAND CKPT_HDR_SIGHAND
	CKPT_HDR_SIGNAL,
#define CKPT_HDR_SIGNAL CKPT_HDR_SIGNAL
	CKPT_HDR_SIGNAL_TASK,
#define CKPT_HDR_SIGNAL_TASK CKPT_HDR_SIGNAL_TASK
	CKPT_HDR_SIGPENDING,
#define CKPT_HDR_SIGPENDING CKPT_HDR_SIGPENDING

	CKPT_HDR_SOCKET = 701,
#define CKPT_HDR_SOCKET CKPT_HDR_SOCKET
	CKPT_HDR_SOCKET_QUEUE,
#define CKPT_HDR_SOCKET_QUEUE CKPT_HDR_SOCKET_QUEUE
	CKPT_HDR_SOCKET_BUFFER,
#define CKPT_HDR_SOCKET_BUFFER CKPT_HDR_SOCKET_BUFFER
	CKPT_HDR_SOCKET_FRAG,
#define CKPT_HDR_SOCKET_FRAG CKPT_HDR_SOCKET_FRAG
	CKPT_HDR_SOCKET_UNIX,
#define CKPT_HDR_SOCKET_UNIX CKPT_HDR_SOCKET_UNIX
	CKPT_HDR_SOCKET_INET,
#define CKPT_HDR_SOCKET_INET CKPT_HDR_SOCKET_INET
	CKPT_HDR_NET_NS,
#define CKPT_HDR_NET_NS CKPT_HDR_NET_NS
	CKPT_HDR_NETDEV,
#define CKPT_HDR_NETDEV CKPT_HDR_NETDEV
	CKPT_HDR_NETDEV_ADDR,
#define CKPT_HDR_NETDEV_ADDR CKPT_HDR_NETDEV_ADDR

	CKPT_HDR_TAIL = 9001,
#define CKPT_HDR_TAIL CKPT_HDR_TAIL

	CKPT_HDR_ERROR = 9999,
#define CKPT_HDR_ERROR CKPT_HDR_ERROR
};

/* architecture */
enum {
	/* do not change order (will break ABI) */
	CKPT_ARCH_X86_32 = 1,
#define CKPT_ARCH_X86_32 CKPT_ARCH_X86_32
	CKPT_ARCH_X86_64,
#define CKPT_ARCH_X86_64 CKPT_ARCH_X86_64
	CKPT_ARCH_S390X,
#define CKPT_ARCH_S390X CKPT_ARCH_S390X
};

/* shared objrects (objref) */
struct ckpt_hdr_objref {
	struct ckpt_hdr h;
	__u32 objtype;
	__s32 objref;
} __attribute__((aligned(8)));

/* shared objects types */
enum obj_type {
	CKPT_OBJ_IGNORE = 0,
#define CKPT_OBJ_IGNORE CKPT_OBJ_IGNORE
	CKPT_OBJ_PID,
#define CKPT_OBJ_PID CKPT_OBJ_PID
	CKPT_OBJ_INODE,
#define CKPT_OBJ_INODE CKPT_OBJ_INODE
	CKPT_OBJ_FILE_TABLE,
#define CKPT_OBJ_FILE_TABLE CKPT_OBJ_FILE_TABLE
	CKPT_OBJ_FILE,
#define CKPT_OBJ_FILE CKPT_OBJ_FILE
	CKPT_OBJ_MM,
#define CKPT_OBJ_MM CKPT_OBJ_MM
	CKPT_OBJ_FS,
#define CKPT_OBJ_FS CKPT_OBJ_FS
	CKPT_OBJ_SIGHAND,
#define CKPT_OBJ_SIGHAND CKPT_OBJ_SIGHAND
	CKPT_OBJ_SIGNAL,
#define CKPT_OBJ_SIGNAL CKPT_OBJ_SIGNAL
	CKPT_OBJ_NS,
#define CKPT_OBJ_NS CKPT_OBJ_NS
	CKPT_OBJ_UTS_NS,
#define CKPT_OBJ_UTS_NS CKPT_OBJ_UTS_NS
	CKPT_OBJ_IPC_NS,
#define CKPT_OBJ_IPC_NS CKPT_OBJ_IPC_NS
	CKPT_OBJ_MNT_NS,
#define CKPT_OBJ_MNT_NS CKPT_OBJ_MNT_NS
	CKPT_OBJ_USER_NS,
#define CKPT_OBJ_USER_NS CKPT_OBJ_USER_NS
	CKPT_OBJ_CRED,
#define CKPT_OBJ_CRED CKPT_OBJ_CRED
	CKPT_OBJ_USER,
#define CKPT_OBJ_USER CKPT_OBJ_USER
	CKPT_OBJ_GROUPINFO,
#define CKPT_OBJ_GROUPINFO CKPT_OBJ_GROUPINFO
	CKPT_OBJ_SOCK,
#define CKPT_OBJ_SOCK CKPT_OBJ_SOCK
	CKPT_OBJ_TTY,
#define CKPT_OBJ_TTY CKPT_OBJ_TTY
	CKPT_OBJ_SECURITY_PTR,
#define CKPT_OBJ_SECURITY_PTR CKPT_OBJ_SECURITY_PTR
	CKPT_OBJ_SECURITY,
#define CKPT_OBJ_SECURITY CKPT_OBJ_SECURITY
	CKPT_OBJ_NET_NS,
#define CKPT_OBJ_NET_NS CKPT_OBJ_NET_NS
	CKPT_OBJ_NETDEV,
#define CKPT_OBJ_NETDEV CKPT_OBJ_NETDEV
	CKPT_OBJ_SEM_UNDO,
#define CKPT_OBJ_SEM_UNDO CKPT_OBJ_SEM_UNDO
	CKPT_OBJ_MAX
#define CKPT_OBJ_MAX CKPT_OBJ_MAX
};

/* kernel constants */
struct ckpt_const {
	/* task */
	__u16 task_comm_len;
	/* mm */
	__u16 at_vector_size;
	/* signal */
	__u16 signal_nsig;
	/* uts */
	__u16 uts_sysname_len;
	__u16 uts_nodename_len;
	__u16 uts_release_len;
	__u16 uts_version_len;
	__u16 uts_machine_len;
	__u16 uts_domainname_len;
	/* rlimit */
	__u16 rlimit_nlimits;
	/* tty */
	__u16 n_tty_buf_size;
	__u16 tty_termios_nccs;
} __attribute__((aligned(8)));

/* checkpoint image header */
struct ckpt_hdr_header {
	struct ckpt_hdr h;
	__u64 magic;

	__u16 arch_id;

	__u16 major;
	__u16 minor;
	__u16 patch;
	__u16 rev;

	struct ckpt_const constants;

	__u64 time;	/* when checkpoint taken */
	__u64 uflags;	/* uflags from checkpoint */

	/*
	 * the header is followed by three strings:
	 *   char release[const.uts_release_len];
	 *   char version[const.uts_version_len];
	 *   char machine[const.uts_machine_len];
	 */
} __attribute__((aligned(8)));

/* checkpoint image trailer */
struct ckpt_hdr_tail {
	struct ckpt_hdr h;
	__u64 magic;
} __attribute__((aligned(8)));

/* container configuration section header */
struct ckpt_hdr_container {
	struct ckpt_hdr h;
	/*
	 * the header is followed by the string:
	 *   char lsm_name[SECURITY_NAME_MAX + 1]
	 * plus the CKPT_HDR_LSM_INFO section
	 */
} __attribute__((aligned(8)));;

/* pids array */
struct ckpt_hdr_pids {
	struct ckpt_hdr h;
	__u32 nr_pids;
	__u32 nr_vpids;
	__u32 offset;  /* objref of the first (root) pid */
} __attribute__((aligned(8)));

struct ckpt_pids {
	__u32 depth;
	__s32 numbers[1];
} __attribute__((aligned(8)));

/* task tree */
struct ckpt_hdr_tree {
	struct ckpt_hdr h;
	__u32 nr_tasks;
} __attribute__((aligned(8)));

struct ckpt_task_pids {
	/* These pids are in the root_nsproxy's pid ns */
	__s32 vpid;
	__s32 vppid;
	__s32 vtgid;
	__s32 vpgid;
	__s32 vsid;
	__u32 depth;
} __attribute__((aligned(8)));

/* (negative but not valid error) */
#define CKPT_PID_NULL (-4096) /* null pid pointer */
#define CKPT_PID_ROOT (-4097) /* pid same as root task */

/* task data */
struct ckpt_hdr_task {
	struct ckpt_hdr h;
	__u32 flags;
	__u32 state;
	__u32 exit_state;
	__u32 exit_code;
	__u32 exit_signal;
	__u32 pdeath_signal;

	__u64 set_child_tid;
	__u64 clear_child_tid;
	__u64 sas_ss_sp;
	__u32 sas_ss_size;

	__u32 compat_robust_futex_head_len;
	__u32 compat_robust_futex_list; /* a compat __user ptr */
	__u32 robust_futex_head_len;
	__u64 robust_futex_list; /* a __user ptr */

} __attribute__((aligned(8)));

#define CKPT_PF_FORKNOEXEC 0x1
#define CKPT_PF_SUPERPRIV 0x2
#define CKPT_PF_VALID (CKPT_PF_FORKNOEXEC | CKPT_PF_SUPERPRIV)

/* Posix capabilities */
struct ckpt_capabilities {
	__u32 cap_i_0, cap_i_1; /* inheritable set */
	__u32 cap_p_0, cap_p_1; /* permitted set */
	__u32 cap_e_0, cap_e_1; /* effective set */
	__u32 cap_b_0, cap_b_1; /* bounding set */
	__u32 securebits;
	__u32 padding;
} __attribute__((aligned(8)));

struct ckpt_hdr_task_creds {
	struct ckpt_hdr h;
	__s32 cred_ref;
	__s32 ecred_ref;
} __attribute__((aligned(8)));

struct ckpt_hdr_cred {
	struct ckpt_hdr h;
	__u32 uid, suid, euid, fsuid;
	__u32 gid, sgid, egid, fsgid;
	__s32 user_ref;
	__s32 groupinfo_ref;
	__s32 sec_ref;
	struct ckpt_capabilities cap_s;
} __attribute__((aligned(8)));

struct ckpt_hdr_groupinfo {
	struct ckpt_hdr h;
	__u32 ngroups;
	/*
	 * This is followed by ngroups __u32s
	 */
	__u32 groups[0];
} __attribute__((aligned(8)));

struct ckpt_hdr_lsm {
	struct ckpt_hdr h;
	__s32 ptrref;
	__u8 sectype;
	/*
	 * This is followed by a string of size len+1,
	 * null-terminated
	 */
} __attribute__((aligned(8)));
/*
 * todo - keyrings and LSM
 * These may be better done with userspace help though
 */
struct ckpt_hdr_user_struct {
	struct ckpt_hdr h;
	__u32 uid;
	__s32 userns_ref;
} __attribute__((aligned(8)));

/*
 * The user-struct mostly tracks system resource usage.
 * Most of it's contents therefore will simply be set
 * correctly as restart opens resources
 */
struct ckpt_hdr_user_ns {
	struct ckpt_hdr h;
	__s32 creator_ref;
} __attribute__((aligned(8)));

/* namespaces */
struct ckpt_hdr_task_ns {
	struct ckpt_hdr h;
	__s32 ns_objref;
} __attribute__((aligned(8)));

struct ckpt_hdr_ns {
	struct ckpt_hdr h;
	__s32 uts_objref;
	__s32 ipc_objref;
	__s32 net_objref;
} __attribute__((aligned(8)));

struct ckpt_hdr_task_sem_undo_list {
	struct ckpt_hdr h;
	__u32 count;
};

struct ckpt_hdr_task_sem_undo {
	struct ckpt_hdr h;
	__u32 semid;
	__u32 semadj_count;
};

/* cannot include <linux/tty.h> from userspace, so define: */
#define CKPT_NEW_UTS_LEN 64

struct ckpt_hdr_utsns {
	struct ckpt_hdr h;
	char sysname[CKPT_NEW_UTS_LEN + 1];
	char nodename[CKPT_NEW_UTS_LEN + 1];
	char release[CKPT_NEW_UTS_LEN + 1];
	char version[CKPT_NEW_UTS_LEN + 1];
	char machine[CKPT_NEW_UTS_LEN + 1];
	char domainname[CKPT_NEW_UTS_LEN + 1];
} __attribute__((aligned(8)));

/* task's shared resources */
struct ckpt_hdr_task_objs {
	struct ckpt_hdr h;

	__s32 files_objref;
	__s32 mm_objref;
	__s32 fs_objref;
	__s32 sem_undo_objref;
	__s32 sighand_objref;
	__s32 signal_objref;
} __attribute__((aligned(8)));

/* restart blocks */
struct ckpt_hdr_restart_block {
	struct ckpt_hdr h;
	__u64 function_type;
	__u64 arg_0;
	__u64 arg_1;
	__u64 arg_2;
	__u64 arg_3;
	__u64 arg_4;
} __attribute__((aligned(8)));

enum restart_block_type {
	CKPT_RESTART_BLOCK_NONE = 1,
#define CKPT_RESTART_BLOCK_NONE CKPT_RESTART_BLOCK_NONE
	CKPT_RESTART_BLOCK_HRTIMER_NANOSLEEP,
#define CKPT_RESTART_BLOCK_HRTIMER_NANOSLEEP CKPT_RESTART_BLOCK_HRTIMER_NANOSLEEP

	CKPT_RESTART_BLOCK_POSIX_CPU_NANOSLEEP,
#define CKPT_RESTART_BLOCK_POSIX_CPU_NANOSLEEP CKPT_RESTART_BLOCK_POSIX_CPU_NANOSLEEP

	CKPT_RESTART_BLOCK_COMPAT_NANOSLEEP,
#define CKPT_RESTART_BLOCK_COMPAT_NANOSLEEP CKPT_RESTART_BLOCK_COMPAT_NANOSLEEP

	CKPT_RESTART_BLOCK_COMPAT_CLOCK_NANOSLEEP,
#define CKPT_RESTART_BLOCK_COMPAT_CLOCK_NANOSLEEP CKPT_RESTART_BLOCK_COMPAT_CLOCK_NANOSLEEP

	CKPT_RESTART_BLOCK_POLL,
#define CKPT_RESTART_BLOCK_POLL CKPT_RESTART_BLOCK_POLL
	CKPT_RESTART_BLOCK_FUTEX,
#define CKPT_RESTART_BLOCK_FUTEX CKPT_RESTART_BLOCK_FUTEX
};

/* file system */
struct ckpt_hdr_fs {
	struct ckpt_hdr h;
	__u32 umask;
	/* char *fs_root */
	/* char *fs_pwd */
} __attribute__((aligned(8)));

struct ckpt_hdr_file_table {
	struct ckpt_hdr h;
	__s32 fdt_nfds;
} __attribute__((aligned(8)));

/* file descriptors */
struct ckpt_hdr_file_desc {
	struct ckpt_hdr h;
	__s32 fd_objref;
	__s32 fd_descriptor;
	__u32 fd_close_on_exec;
} __attribute__((aligned(8)));

enum file_type {
	CKPT_FILE_IGNORE = 0,
#define CKPT_FILE_IGNORE CKPT_FILE_IGNORE
	CKPT_FILE_GENERIC,
#define CKPT_FILE_GENERIC CKPT_FILE_GENERIC
	CKPT_FILE_PIPE,
#define CKPT_FILE_PIPE CKPT_FILE_PIPE
	CKPT_FILE_FIFO,
#define CKPT_FILE_FIFO CKPT_FILE_FIFO
	CKPT_FILE_SOCKET,
#define CKPT_FILE_SOCKET CKPT_FILE_SOCKET
	CKPT_FILE_TTY,
#define CKPT_FILE_TTY CKPT_FILE_TTY
	CKPT_FILE_EPOLL,
#define CKPT_FILE_EPOLL CKPT_FILE_EPOLL
	CKPT_FILE_EVENTFD,
#define CKPT_FILE_EVENTFD CKPT_FILE_EVENTFD
	CKPT_FILE_MAX
#define CKPT_FILE_MAX CKPT_FILE_MAX
};

/* file objects */
struct ckpt_hdr_file {
	struct ckpt_hdr h;
	__u32 f_type;
	__u32 f_mode;
	__u32 f_flags;
	__s32 f_credref;
	__u64 f_pos;
	__u64 f_version;
	__s32 f_secref;
} __attribute__((aligned(8)));

struct ckpt_hdr_file_generic {
	struct ckpt_hdr_file common;
} __attribute__((aligned(8)));

struct ckpt_hdr_file_pipe {
	struct ckpt_hdr_file common;
	__s32 pipe_objref;
} __attribute__((aligned(8)));

struct ckpt_hdr_file_eventfd {
	struct ckpt_hdr_file common;
	__u64 count;
	__u32 flags;
} __attribute__((aligned(8)));

/* socket */
struct ckpt_hdr_socket {
	struct ckpt_hdr h;

	__u8 has_buffers;

	struct { /* struct socket */
		__u64 flags;
		__u8 state;
	} socket __attribute__ ((aligned(8)));

	struct { /* struct sock_common */
		__u32 bound_dev_if;
		__u32 reuse;
		__u16 family;
		__u8 state;
	} sock_common __attribute__ ((aligned(8)));

	struct { /* struct sock */
		__s64 rcvlowat;
		__u64 flags;

		__s64 rcvtimeo;
		__s64 sndtimeo;

		__u32 err;
		__u32 err_soft;
		__u32 priority;
		__s32 rcvbuf;
		__s32 sndbuf;
		__u16 type;
		__s16 backlog;

		__u8 protocol;
		__u8 state;
		__u8 shutdown;
		__u8 userlocks;
		__u8 no_check;

		struct linger linger;
	} sock __attribute__ ((aligned(8)));
} __attribute__ ((aligned(8)));

struct ckpt_hdr_socket_queue {
	struct ckpt_hdr h;
	__u32 skb_count;
	__u32 total_bytes;
} __attribute__ ((aligned(8)));

struct ckpt_hdr_socket_buffer {
	struct ckpt_hdr h;
	__u32 transport_header;
	__u32 network_header;
	__u32 mac_header;
	__u32 lin_len; /* Length of linear data */
	__u32 frg_len; /* Length of fragment data */
	__u32 skb_len; /* Length of skb (adjusted) */
	__u32 hdr_len; /* Length of skipped header */
	__u32 mac_len;
	__u32 data_offset; /* Offset of data pointer from head */
	__s32 sk_objref;
	__s32 pr_objref;
	__u16 protocol;
	__u16 nr_frags;
	__u8 cb[48];
};

struct ckpt_hdr_socket_buffer_frag {
	struct ckpt_hdr h;
	__u32 size;
	__u32 offset;
};

#define CKPT_UNIX_LINKED 1
struct ckpt_hdr_socket_unix {
	struct ckpt_hdr h;
	__s32 this;
	__s32 peer;
	__s32 peercred;
	__u32 flags;
	__u32 laddr_len;
	__u32 raddr_len;
	struct sockaddr_un laddr;
	struct sockaddr_un raddr;
} __attribute__ ((aligned(8)));

struct ckpt_hdr_socket_inet {
	struct ckpt_hdr h;
	__u32 daddr;
	__u32 rcv_saddr;
	__u32 saddr;
	__u16 dport;
	__u16 num;
	__u16 sport;
	__s16 uc_ttl;
	__u16 cmsg_flags;

	struct {
		__u64 timeout;
		__u32 ato;
		__u32 lrcvtime;
		__u16 last_seg_size;
		__u16 rcv_mss;
		__u8 pending;
		__u8 quick;
		__u8 pingpong;
		__u8 blocked;
	} icsk_ack __attribute__ ((aligned(8)));

	/* FIXME: Skipped opt, tos, multicast, cork settings */

	struct {
		__u32 rcv_nxt;
		__u32 copied_seq;
		__u32 rcv_wup;
		__u32 snd_nxt;
		__u32 snd_una;
		__u32 snd_sml;
		__u32 rcv_tstamp;
		__u32 lsndtime;

		__u32 snd_wl1;
		__u32 snd_wnd;
		__u32 max_window;
		__u32 mss_cache;
		__u32 window_clamp;
		__u32 rcv_ssthresh;
		__u32 frto_highmark;

		__u32 srtt;
		__u32 mdev;
		__u32 mdev_max;
		__u32 rttvar;
		__u32 rtt_seq;

		__u32 packets_out;
		__u32 retrans_out;

		__u32 snd_up;
		__u32 rcv_wnd;
		__u32 write_seq;
		__u32 pushed_seq;
		__u32 lost_out;
		__u32 sacked_out;
		__u32 fackets_out;
		__u32 tso_deferred;
		__u32 bytes_acked;

		__s32 lost_cnt_hint;
		__u32 retransmit_high;

		__u32 lost_retrans_low;

		__u32 prior_ssthresh;
		__u32 high_seq;

		__u32 retrans_stamp;
		__u32 undo_marker;
		__s32 undo_retrans;
		__u32 total_retrans;

		__u32 urg_seq;
		__u32 keepalive_time;
		__u32 keepalive_intvl;

		__u16 urg_data;
		__u16 advmss;
		__u8 frto_counter;
		__u8 nonagle;

		__u8 ecn_flags;
		__u8 reordering;

		__u8 keepalive_probes;
	} tcp __attribute__ ((aligned(8)));

	struct {
		struct in6_addr saddr;
		struct in6_addr rcv_saddr;
		struct in6_addr daddr;
	} inet6 __attribute__ ((aligned(8)));

	__u32 laddr_len;
	__u32 raddr_len;
	struct sockaddr_in laddr;
	struct sockaddr_in raddr;
} __attribute__((aligned(8)));

struct ckpt_hdr_file_socket {
	struct ckpt_hdr_file common;
	__s32 sock_objref;
} __attribute__((aligned(8)));

struct ckpt_hdr_netns {
	struct ckpt_hdr h;
	__s32 this_ref;
} __attribute__((aligned(8)));

enum ckpt_netdev_types {
	CKPT_NETDEV_LO,
	CKPT_NETDEV_VETH,
	CKPT_NETDEV_SIT,
	CKPT_NETDEV_MACVLAN,
	CKPT_NETDEV_MAX,
};

struct ckpt_hdr_netdev {
	struct ckpt_hdr h;
	__s32 netns_ref;
	union {
		struct {
			__s32 this_ref;
			__s32 peer_ref;
		} veth;
		struct {
			__u32 mode;
		} macvlan;
	};
	__u32 inet_addrs;
	__u16 type;
	__u16 flags;
	__u8 hwaddr[6];
} __attribute__((aligned(8)));

enum ckpt_netdev_addr_types {
	CKPT_NETDEV_ADDR_IPV4,
};

struct ckpt_netdev_addr {
	__u16 type;
	union {
		struct {
			__be32 inet4_local;
			__be32 inet4_address;
			__be32 inet4_mask;
			__be32 inet4_broadcast;
		};
	} __attribute__((aligned(8)));
} __attribute__((aligned(8)));

struct ckpt_hdr_eventpoll_items {
	struct ckpt_hdr h;
	__s32  epfile_objref;
	__u32  num_items;
} __attribute__((aligned(8)));

/* Contained in a CKPT_HDR_BUFFER following the ckpt_hdr_eventpoll_items */
struct ckpt_eventpoll_item {
	__u64 data;
	__u32 fd;
	__s32 file_objref;
	__u32 events;
} __attribute__((aligned(8)));

/* memory layout */
struct ckpt_hdr_mm {
	struct ckpt_hdr h;
	__u32 map_count;
	__s32 exe_objref;

	__u64 def_flags;
	__u64 flags;

	__u64 start_code, end_code, start_data, end_data;
	__u64 start_brk, brk, start_stack;
	__u64 arg_start, arg_end, env_start, env_end;
} __attribute__((aligned(8)));

/* vma subtypes - index into restore_vma_dispatch[] */
enum vma_type {
	CKPT_VMA_IGNORE = 0,
#define CKPT_VMA_IGNORE CKPT_VMA_IGNORE
	CKPT_VMA_VDSO,		/* special vdso vma */
#define CKPT_VMA_VDSO CKPT_VMA_VDSO
	CKPT_VMA_ANON,		/* private anonymous */
#define CKPT_VMA_ANON CKPT_VMA_ANON
	CKPT_VMA_FILE,		/* private mapped file */
#define CKPT_VMA_FILE CKPT_VMA_FILE
	CKPT_VMA_SHM_ANON,	/* shared anonymous */
#define CKPT_VMA_SHM_ANON CKPT_VMA_SHM_ANON
	CKPT_VMA_SHM_ANON_SKIP,	/* shared anonymous (skip contents) */
#define CKPT_VMA_SHM_ANON_SKIP CKPT_VMA_SHM_ANON_SKIP
	CKPT_VMA_SHM_FILE,	/* shared mapped file, only msync */
#define CKPT_VMA_SHM_FILE CKPT_VMA_SHM_FILE
	CKPT_VMA_SHM_IPC,	/* shared sysvipc */
#define CKPT_VMA_SHM_IPC CKPT_VMA_SHM_IPC
	CKPT_VMA_SHM_IPC_SKIP,	/* shared sysvipc (skip contents) */
#define CKPT_VMA_SHM_IPC_SKIP CKPT_VMA_SHM_IPC_SKIP
	CKPT_VMA_HUGETLB,
#define CKPT_VMA_HUGETLB CKPT_VMA_HUGETLB
	CKPT_VMA_HUGETLB_SKIP,
#define CKPT_VMA_HUGETLB_SKIP CKPT_VMA_HUGETLB_SKIP
};

/* vma descriptor */
struct ckpt_hdr_vma {
	struct ckpt_hdr h;
	__u32 vma_type;
	__s32 vma_objref;	/* objref of backing file */
	__s32 ino_objref;	/* objref of shared segment */
	__u32 _padding;
	__u64 ino_size;		/* size of shared segment */

	__u64 vm_start;
	__u64 vm_end;
	__u64 vm_page_prot;
	__u64 vm_flags;
	__u64 vm_pgoff;

	__u16 hugetlb_shift;
} __attribute__((aligned(8)));

/* page array */
struct ckpt_hdr_pgarr {
	struct ckpt_hdr h;
	__u64 nr_pages;		/* number of pages to saved */
} __attribute__((aligned(8)));

/* huge page */
struct ckpt_hdr_hpage {
	struct ckpt_hdr h;
	union {
		__u64 vaddr;
		__u64 index;
	};
	__u16 shift;
} __attribute__((aligned(8)));

/* signals */
struct ckpt_sigset {
	__u8 sigset[CKPT_ARCH_NSIG / 8];
} __attribute__((aligned(8)));

struct ckpt_sigaction {
	__u64 _sa_handler;
	__u64 sa_flags;
	__u64 sa_restorer;
	struct ckpt_sigset sa_mask;
} __attribute__((aligned(8)));

struct ckpt_hdr_sighand {
	struct ckpt_hdr h;
	struct ckpt_sigaction action[0];
} __attribute__((aligned(8)));

struct ckpt_siginfo {
	__u32 csi_signo;
	__s32 csi_errno;
	__s32 csi_code;
	__u32 csi_pid;
	__u32 csi_uid;
	__s32 csi_fd;
	__u32 csi_tid;
	__u32 csi_band;
	__u32 csi_overrun;
	__u32 csi_trapno;
	__s32 csi_status;
	__s32 csi_int;
	__u64 csi_ptr;
	__u64 csi_utime;
	__u64 csi_stime;
	__u64 csi_addr;
	__s32 csi_sys_private; /* POSIX.1b timers */
} __attribute__((aligned(8)));

struct ckpt_hdr_sigpending {
	struct ckpt_hdr h;
	__u32 nr_pending;
	struct ckpt_sigset signal;
	struct ckpt_siginfo siginfo[0];
} __attribute__((aligned(8)));

struct ckpt_rlimit {
	__u64 rlim_cur;
	__u64 rlim_max;
} __attribute__((aligned(8)));

/* cannot include <linux/resource.h> from userspace, so define: */
#define CKPT_RLIM_NLIMITS 16

struct ckpt_hdr_signal {
	struct ckpt_hdr h;
	/* rlimit */
	struct ckpt_rlimit rlim[CKPT_RLIM_NLIMITS];
	/* itimer */
	__u64 it_real_value;
	__u64 it_real_incr;
	__u64 it_virt_value;
	__u64 it_virt_incr;
	__u64 it_prof_value;
	__u64 it_prof_incr;
	/* tty */
	__s32 tty_objref;
	__s32 tty_pgrp;
	__s32 tty_old_pgrp;
} __attribute__((aligned(8)));

struct ckpt_hdr_signal_task {
	struct ckpt_hdr h;
	struct ckpt_sigset blocked;
} __attribute__((aligned(8)));

/* ipc commons */
struct ckpt_hdr_ipcns {
	struct ckpt_hdr h;
	__u64 shm_ctlmax;
	__u64 shm_ctlall;
	__s32 shm_ctlmni;

	__s32 msg_ctlmax;
	__s32 msg_ctlmnb;
	__s32 msg_ctlmni;

	__s32 sem_ctl_msl;
	__s32 sem_ctl_mns;
	__s32 sem_ctl_opm;
	__s32 sem_ctl_mni;
} __attribute__((aligned(8)));

struct ckpt_hdr_ipc {
	struct ckpt_hdr h;
	__u32 ipc_type;
	__u32 ipc_count;
} __attribute__((aligned(8)));

struct ckpt_hdr_ipc_perms {
	struct ckpt_hdr h;
	__s32 id;
	__u32 key;
	__u32 uid;
	__u32 gid;
	__u32 cuid;
	__u32 cgid;
	__u32 mode;
	__u32 _padding;
	__u64 seq;
	__s32 sec_ref;
} __attribute__((aligned(8)));

struct ckpt_hdr_ipc_shm {
	struct ckpt_hdr h;
	struct ckpt_hdr_ipc_perms perms;
	__u64 shm_segsz;
	__u64 shm_atim;
	__u64 shm_dtim;
	__u64 shm_ctim;
	__s32 shm_cprid;
	__s32 shm_lprid;
	__u32 mlock_uid;
	__u32 flags;
	__u32 objref;
	__u16 shift;  /* hugetlb */
} __attribute__((aligned(8)));

struct ckpt_hdr_ipc_msg {
	struct ckpt_hdr h;
	struct ckpt_hdr_ipc_perms perms;
	__u64 q_stime;
	__u64 q_rtime;
	__u64 q_ctime;
	__u64 q_cbytes;
	__u64 q_qnum;
	__u64 q_qbytes;
	__s32 q_lspid;
	__s32 q_lrpid;
} __attribute__((aligned(8)));

struct ckpt_hdr_ipc_msg_msg {
	struct ckpt_hdr h;
	__s64 m_type;
	__u32 m_ts;
	__s32 sec_ref;
} __attribute__((aligned(8)));

struct ckpt_hdr_ipc_sem {
	struct ckpt_hdr h;
	struct ckpt_hdr_ipc_perms perms;
	__u64 sem_otime;
	__u64 sem_ctime;
	__u32 sem_nsems;
} __attribute__((aligned(8)));

/* devices */
struct ckpt_hdr_file_tty {
	struct ckpt_hdr_file common;
	__s32 tty_objref;
};

struct ckpt_hdr_tty {
	struct ckpt_hdr h;

	__u16 driver_type;
	__u16 driver_subtype;

	__s32 link_objref;
	__s32 file_objref;
	__u32 _padding;

	__u32 index;
	__u32 ldisc;
	__u64 flags;

	/* termios */
	struct {
		__u32 c_iflag;
		__u32 c_oflag;
		__u32 c_cflag;
		__u32 c_lflag;
		__u32 c_ispeed;
		__u32 c_ospeed;
		__u8 c_line;
		__u8 c_cc[NCCS];
	} __attribute__((aligned(8))) termios;

	/* winsize */
	struct {
		__u16 ws_row;
		__u16 ws_col;
		__u16 ws_xpixel;
		__u16 ws_ypixel;
	} __attribute__((aligned(8))) winsize;
} __attribute__((aligned(8)));

/* cannot include <linux/tty.h> from userspace, so define: */
#define CKPT_N_TTY_BUF_SIZE 4096

struct ckpt_hdr_ldisc_n_tty {
	struct ckpt_hdr h;

	__u32 column;
	__u32 datalen;
	__u32 canon_column;
	__u32 canon_datalen;
	__u32 canon_data;

	__u16 minimum_to_wake;

	__u8 stopped;
	__u8 hw_stopped;
	__u8 flow_stopped;
	__u8 packet;
	__u8 ctrl_status;
	__u8 lnext;
	__u8 erasing;
	__u8 raw;
	__u8 real_raw;
	__u8 icanon;
	__u8 closing;
	__u8 padding[3];

	__u8 read_flags[CKPT_N_TTY_BUF_SIZE / 8];

	/* if @datalen > 0, buffer contents follow (next object) */
} __attribute__((aligned(8)));

#define CKPT_TST_OVERFLOW_16(a,b) ((sizeof(a) > sizeof(b)) && ((a) > SHRT_MAX))

#define CKPT_TST_OVERFLOW_32(a,b) ((sizeof(a) > sizeof(b)) && ((a) > INT_MAX))

#define CKPT_TST_OVERFLOW_64(a,b) ((sizeof(a) > sizeof(b)) && ((a) > LONG_MAX))


#endif /* _CHECKPOINT_CKPT_HDR_H_ */
