#include <stdio.h>
#include <signal.h>

#define BUFSIZE  (4096)

static inline void ckpt_msg(int fd, char *format, ...)
{
	char buf[BUFSIZE];
	va_list ap;
	int err;

	if (fd < 0)
		return;

	va_start(ap, format);
	vsnprintf(buf, BUFSIZE, format, ap);
	va_end(ap);

	err = errno;
	write(fd, buf, strlen(buf));
	errno = err;
}

static void inline _strerror(int errnum, char *buf, size_t buflen)
{
	/*
	 * Because strerror_r() comes in two flavors, each with
	 * different behavior (see man-page), we must select one
	 */
#if  (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE)
	/* the XSI-compliant flavor */
	strerror_r(errnum, buf, buflen);
#else
	/* the GNU-specific version */
	char *err = strerror_r(errnum, buf, buflen);
	if (err != buf) {
		while (*err && --buflen)
			*buf++ = *err++;
		*buf = '\0';
	}
#endif
}

#define ckpt_perror(s)						\
	do {							\
		char __buf[256];				\
		_strerror(errno, __buf, 256);			\
		ckpt_msg(global_uerrfd, "%s: %s\n", s, __buf);	\
	} while (0)

#ifdef CHECKPOINT_DEBUG
#define ckpt_dbg(_format, _args...)					\
	do {								\
		if (global_debug)					\
			ckpt_msg(global_uerrfd, "<%d>" _format, 	\
					_gettid(), ##_args); 		\
	} while (0)
#define ckpt_dbg_cont(_format, _args...)				\
	do {								\
		if (global_debug)					\
			ckpt_msg(global_uerrfd, _format, ##_args);	\
	} while (0)
#else
#define ckpt_dbg(_format, _args...)  \
	do { } while (0)
#define ckpt_dbg_cont(_format, _args...)  \
	do { } while (0)
#endif

#define ckpt_err(...)  \
	ckpt_msg(global_uerrfd, __VA_ARGS__)

#define ckpt_verbose(...)					\
	do {							\
		if (global_verbose)				\
			ckpt_msg(global_ulogfd, __VA_ARGS__);	\
	} while(0)

struct signal_array {
	int signum;
	char *sigstr;
};

#define SIGNAL_ENTRY(signal)  { SIG ## signal, #signal }

#define INIT_SIGNAL_ARRAY { 	\
	{ 0, "NONE" },		\
	SIGNAL_ENTRY(ALRM),	\
	SIGNAL_ENTRY(HUP),	\
	SIGNAL_ENTRY(INT),	\
	SIGNAL_ENTRY(KILL),	\
	SIGNAL_ENTRY(PIPE),	\
	SIGNAL_ENTRY(POLL),	\
	SIGNAL_ENTRY(PROF),	\
	SIGNAL_ENTRY(TERM),	\
	SIGNAL_ENTRY(USR1),	\
	SIGNAL_ENTRY(USR2),	\
	SIGNAL_ENTRY(VTALRM),	\
	SIGNAL_ENTRY(STKFLT),	\
	SIGNAL_ENTRY(PWR),	\
	SIGNAL_ENTRY(WINCH),	\
	SIGNAL_ENTRY(CHLD),	\
	SIGNAL_ENTRY(URG),	\
	SIGNAL_ENTRY(TTIN),	\
	SIGNAL_ENTRY(TTOU),	\
	SIGNAL_ENTRY(STOP),	\
	SIGNAL_ENTRY(CONT),	\
	SIGNAL_ENTRY(ABRT),	\
	SIGNAL_ENTRY(FPE),	\
	SIGNAL_ENTRY(ILL),	\
	SIGNAL_ENTRY(QUIT),	\
	SIGNAL_ENTRY(SEGV),	\
	SIGNAL_ENTRY(TRAP),	\
	SIGNAL_ENTRY(SYS),	\
	SIGNAL_ENTRY(BUS),	\
	SIGNAL_ENTRY(XCPU),	\
	SIGNAL_ENTRY(XFSZ),	\
	{ -1, "LAST" },		\
}

#define CKPT_COND_PIDZERO  0x1
#define CKPT_COND_MNTPROC  0x2
#define CKPT_COND_MNTPTY   0x4

#define CKPT_COND_NONE     0
#define CKPT_COND_ANY      ULONG_MAX

/* default for skip/warn/fail */
#define CKPT_COND_WARN     (CKPT_COND_MNTPROC | \
			    CKPT_COND_MNTPTY)
#define CKPT_COND_FAIL     (CKPT_COND_NONE)

