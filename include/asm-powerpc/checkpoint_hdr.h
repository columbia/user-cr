/*
 * Generated by extract-headers.sh.
 */
#ifndef __ASM_POWERPC_CHECKPOINT_HDR_H_
#define __ASM_POWERPC_CHECKPOINT_HDR_H_


#include <linux/types.h>

/* arch dependent constants */
#define CKPT_ARCH_NSIG 64
#define CKPT_TTY_NCC 10

struct ckpt_hdr_header_arch {
	struct ckpt_hdr h;
	__u32 what;
} __attribute__((aligned(8)));



#endif /* __ASM_POWERPC_CHECKPOINT_HDR_H_ */