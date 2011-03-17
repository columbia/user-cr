#!/bin/bash
#
# Copyright (C) 2009 IBM Corp.
# Author: Matt Helsley <matthltc@us.ibm.com>
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file COPYING in the main directory of the Linux
# distribution for more details.
#

#
# Sanitize checkpoint/restart kernel headers for userspace.
#

function usage()
{
	echo "Usage: $0 [-h|--help] -s|--kernel-src=DIR"
}

OUTPUT_INCLUDES="include"
OPTIONS=`getopt -o s:o:h --long kernel-src:,output:,help -- "$@"`
eval set -- "${OPTIONS}"
while true ; do
	case "$1" in
	-s|--kernel-src)
		KERNELSRC="$2"
		shift 2 ;;
	-o|--output)
		OUTPUT_INCLUDES="$2"
		shift 2 ;;
	-h|--help)
		usage
		exit 0 ;;
	--)
		shift
		break ;;
	*)
		echo "Unknown option: $1"
		shift
		echo "Unparsed options: $@"
		usage 1>&2
		exit 2 ;;
	esac
done

if [ -z "${KERNELSRC}" -o '!' -d "${KERNELSRC}" ]; then
	usage 1>&2
	exit 2
fi

# Match cpp includes
INCLUDE_PRE_REGEX='#[ \t]*include[ \t]*\([<"]'
INCLUDE_FILE_REGEX='[^">]*'
INCLUDE_POST_REGEX='[">]\)'

# Match cpp includes with \1 being the included file
INCLUDE_REGEX="${INCLUDE_PRE_REGEX}${INCLUDE_FILE_REGEX}${INCLUDE_POST_REGEX}"

# Match includes of linux/types.h (\1 == linux/types.h)
INCLUDE_LINUX_TYPES_REGEX="${INCLUDE_PRE_REGEX}linux\/types\.h${INCLUDE_POST_REGEX}"

# Match includes of linux/* with \1 being everything preceding "linux/" and \2
# being everything following "linux/"
INCLUDE_LINUX_REGEX="${INCLUDE_PRE_REGEX}"'\)'"linux\/"'\('"${INCLUDE_FILE_REGEX}${INCLUDE_POST_REGEX}"

#
# Run the kernel header through cpp to strip out __KERNEL__ sections but try
# to leave the rest untouched.
#
function do_cpp ()
{
	local CPP_FILE="$1"
	local START_DEFINE="$2"
	shift 2

	#
	# Hide #include directives then run cpp. Make cpp keep comments, not
	# insert line numbers, avoid system/gcc/std defines, and only expand
	# directives. Strip cpp output until we get to #define START_DEFINE,
	# and collapse the excessive number of blank lines that cpp outputs
	# in place of directives. Finally, replace linux/ with sys/ prefixes
	# of include paths, except for linux/types.h (needed for __uXX types).
	#
	sed -e 's|'"${INCLUDE_REGEX}"'|/*#include \1*/|g' "${CPP_FILE}" | \
	cpp -CC -P -U__KERNEL__ -undef -nostdinc -fdirectives-only -dDI "$@" | \
	awk 'BEGIN { do_print = 0; }
	     /#[ \t]*define '"${START_DEFINE}"'/  { do_print = 1; next; }
	     (do_print == 1)				{ print }' | \
	cat -s | \
	sed -e 's|/\*'"${INCLUDE_REGEX}"'\*/|#include \1|g' | \
	sed -e "/${INCLUDE_LINUX_TYPES_REGEX}/n" \
	    -e "s|${INCLUDE_LINUX_REGEX}|#include \1sys/\2|"
	echo ''
}

# Map KARCH to something suitable for CPP e.g. __i386__
function karch_to_cpparch ()
{
	local KARCH="$1"
	local WORDBITS="$2"
	shift 2;

	case "${KARCH}" in
	x86)	[ "${WORDBITS}" == "32" ] && echo -n "i386"
		[ "${WORDBITS}" == "64" ] && echo -n "x86_64"
		[ -z "${WORDBITS}" ]      && echo -n 'i386__ || __x86_64' # HACK
		;;
	s390*)	echo -n "s390x" ;;
	*)	echo -n "${KARCH}" ;;
	esac
	return 0
}

set -e

mkdir -p "${OUTPUT_INCLUDES}/linux"
mkdir -p "${OUTPUT_INCLUDES}/asm"

#
# Process include/linux/checkpoint_hdr.h -> include/linux/checkpoint_hdr.h
#
cat - > "${OUTPUT_INCLUDES}/linux/checkpoint_hdr.h" <<-EOFOO
/*
 * Generated by $(basename "$0").
 */
#ifndef _CHECKPOINT_CKPT_HDR_H_
#define _CHECKPOINT_CKPT_HDR_H_

#include <unistd.h>
EOFOO

do_cpp "${KERNELSRC}/include/linux/checkpoint_hdr.h" "_CHECKPOINT_CKPT_HDR_H_" \
>> "${OUTPUT_INCLUDES}/linux/checkpoint_hdr.h"
echo '#endif /* _CHECKPOINT_CKPT_HDR_H_ */' >> "${OUTPUT_INCLUDES}/linux/checkpoint_hdr.h"

#
# Process include/linux/checkpoint.h -> include/linux/checkpoint.h
#     and arch/*/include/asm/unistd.h -> include/linux/checkpoint.h.
# Eventually the unistd.h portion will get into the glibc headers and
# we can drop that part of this script.
#

(
#
# We use ARCH_COND to break up architecture-specific sections of the header.
#
ARCH_COND='#if'
ARM_SYSCALL_BASE="#	define __NR_OABI_SYSCALL_BASE 0x900000\n\
#	if defined(__thumb__) || defined(__ARM_EABI__)\n\
#		define __NR_SYSCALL_BASE	0\n\
#	else\n\
#		define __NR_SYSCALL_BASE	__NR_OABI_SYSCALL_BASE\n\
#	endif\n"

# Get the regular expression for the current architecture
function get_unistd_regex()
{
	local SYS_NR_DEF_REGEX='[[:space:]]*#[[:space:]]*define[[:space:]]*__NR_(checkpoint|restart|eclone)[[:space:]]+'

	case "$1" in
	arm)	echo -n "${SYS_NR_DEF_REGEX}"
		echo -n '\(__NR_SYSCALL_BASE\+[[:space:]]*[0-9]*\)'
		;;
	*)	echo -n "${SYS_NR_DEF_REGEX}"'[0-9]+'
		;;
	esac
	return 0
}

cat - <<-EOFOE
/*
 * Generated by $(basename "$0").
 */
#ifndef _LINUX_CHECKPOINT_H_
#define _LINUX_CHECKPOINT_H_

#include <unistd.h>
EOFOE

do_cpp "${KERNELSRC}/include/linux/checkpoint.h" "_LINUX_CHECKPOINT_H_"

find "${KERNELSRC}/arch" -name 'unistd*.h' -print | sort | \
while read UNISTDH ; do
	[ -n "${UNISTDH}" ] || continue
	KARCH=$(echo "${UNISTDH}" | sed -e 's|.*/arch/\([^/]\+\)/.*|\1|')
	REGEX="$(get_unistd_regex "${KARCH}")"
	grep -q -E "${REGEX}" "${UNISTDH}" || continue
	WORDBITS=$(basename "${UNISTDH}" | sed -e 's/unistd_*\([[:digit:]]\+\)\.h/\1/')
	CPPARCH="$(karch_to_cpparch "${KARCH}" "${WORDBITS}")"
	echo -e "${ARCH_COND} __${CPPARCH}__\\n"

	[ "${KARCH}" == "arm" ] && echo -e "${ARM_SYSCALL_BASE}\n"

	grep -E "${REGEX}" "${UNISTDH}" | \
	sed -e 's/^[ \t]*#[ \t]*define[ \t]*__NR_\([^ \t]\+\)[ \t]\+\([^ \t]\+\).*$/#\tifndef __NR_\1\n#\t\tdefine __NR_\1 \2\n#\tendif\n/'
	ARCH_COND='#elif'
done

cat - <<-EOFOFOE
#else

#if !defined(__NR_checkpoint) || !defined(__NR_restart)
#error "Architecture does not have definitons for __NR_(checkpoint|restart)"
#endif

#endif
#endif /* _LINUX_CHECKPOINT_H_ */
EOFOFOE

) > "${OUTPUT_INCLUDES}/linux/checkpoint.h"

#
# Process arch/*/include/asm/checkpoint_hdr.h -> include/asm/checkpoint_hdr.h
# Use #if __arch1__ ... #elif __arch2___ ... #endif to wrap each portion.
#
ARCH_COND='#if'

find "${KERNELSRC}/arch" -name 'checkpoint_hdr.h' -print | sort | \
while read ARCH_CHECKPOINT_HDR_H ; do
	[ -n "${ARCH_CHECKPOINT_HDR_H}" ] || continue

	KARCH=$(echo "${ARCH_CHECKPOINT_HDR_H}" | sed -e 's|.*/arch/\([^/]\+\)/.*|\1|')
	UPCASE_KARCH=$(echo "${KARCH}" | tr 'a-z' 'A-Z')
	mkdir -p "${OUTPUT_INCLUDES}/asm-${KARCH}"
	cat - > "${OUTPUT_INCLUDES}/asm-${KARCH}/checkpoint_hdr.h" <<-EOFOEOF
	/*
	 * Generated by $(basename "$0").
	 */
	#ifndef __ASM_${UPCASE_KARCH}_CHECKPOINT_HDR_H_
	#define __ASM_${UPCASE_KARCH}_CHECKPOINT_HDR_H_

	EOFOEOF

	do_cpp "${KERNELSRC}/arch/${KARCH}/include/asm/checkpoint_hdr.h" '__ASM.*_CKPT_HDR_H' -D_CHECKPOINT_CKPT_HDR_H_ >> "${OUTPUT_INCLUDES}/asm-${KARCH}/checkpoint_hdr.h"

	cat - >> "${OUTPUT_INCLUDES}/asm-${KARCH}/checkpoint_hdr.h" <<-FOEOEOF

	#endif /* __ASM_${UPCASE_KARCH}_CHECKPOINT_HDR_H_ */
	FOEOEOF

	ARCH_COND='#elif'
done

#
# Process arch/*/include/asm/checkpoint_hdr.h -> include/asm/checkpoint_hdr.h
# Use #if __arch1__ ... #elif __arch2___ ... #endif to wrap each portion.
#
(
ARCH_COND='#if'

cat - <<-EOFOEOF
/*
 * Generated by $(basename "$0").
 */
#ifndef __ASM_CHECKPOINT_HDR_H_
#define __ASM_CHECKPOINT_HDR_H_
EOFOEOF

find "${KERNELSRC}/arch" -name 'checkpoint_hdr.h' -print | sort | \
while read ARCH_CHECKPOINT_HDR_H ; do
	[ -n "${ARCH_CHECKPOINT_HDR_H}" ] || continue

	KARCH=$(echo "${ARCH_CHECKPOINT_HDR_H}" | sed -e 's|.*/arch/\([^/]\+\)/.*|\1|')
	CPPARCH="$(karch_to_cpparch "${KARCH}" "")"
	cat - <<-EOFOEOF
	${ARCH_COND} __${CPPARCH}__
	#include <asm-${KARCH}/checkpoint_hdr.h>
	EOFOEOF
	ARCH_COND='#elif'
done

cat - <<-FOEOEOF
#else
#error "Architecture does not have definitons needed for checkpoint images."
#endif
#endif /* __ASM_CHECKPOINT_HDR_H_ */
FOEOEOF

) > "${OUTPUT_INCLUDES}/asm/checkpoint_hdr.h"
