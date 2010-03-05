#include <stdio.h>
#include <signal.h>

#define BUFSIZE  (4 * 4096)

static inline void ckpt_msg(int fd, char *format, ...)
{
	va_list ap;
	char *bufp;
	if (fd < 0)
		return;

	va_start(ap, format);

	bufp = malloc(BUFSIZE);
	if(bufp) {
		vsnprintf(bufp, BUFSIZE, format, ap);
		write(fd, bufp, strlen(bufp));
	}
	free(bufp);

	va_end(ap);
}

#define ckpt_perror(s) 							\
	do {								\
		ckpt_msg(global_uerrfd, s);				\
		ckpt_msg(global_uerrfd, ": %s\n", strerror(errno));	\
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

